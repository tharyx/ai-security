"""Model DoS, the model-level kind: context-window exhaustion and amplification.

The context window is a fixed-size box. Everything the model reads must fit: the system
prompt, the history, retrieved documents, the user message, AND room for the answer.

Three failures this lab shows (and fixes):

1. EVICTION. A naive app cuts the OLDEST text when the prompt is too long. The oldest text
   is the system prompt, so a long input silently deletes your rules.
2. BUDGET BLOW-UP. One huge input (or many medium ones) burns tokens and money. Nothing
   stops it, so one user can exhaust capacity for everyone ("denial of wallet").
3. RECURSIVE EXPANSION. A template engine that expands ``{{include:name}}`` references can
   be fed a document that includes itself, or a "billion laughs" tree of includes.

``02-llm-security/security-testing/lab/limits.py`` already has rate limits, per-user budgets
and a loop guard. This lab adds the context-window part those do not cover.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from aisec_lab import Message, MockLLM, REFUSAL

SYSTEM_PROMPT = "You are a billing assistant. Answer billing questions only. Refuse everything else."
INCLUDE_RE = re.compile(r"\{\{include:([a-z0-9_-]+)\}\}")


def estimate_tokens(text: str) -> int:
    """Rough rule: about 4 characters per token for English."""
    return max(1, math.ceil(len(text) / 4))


class PolicyLLM(MockLLM):
    """Refuses off-topic requests, but ONLY while the policy text is still in its context."""

    def complete(self, messages: list[Message]) -> str:
        has_policy = any("billing questions only" in m["content"] for m in messages)
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        if "billing" in last_user.lower() and "invoice" in last_user.lower():
            return "Your invoice is available in the portal."
        if has_policy:
            return REFUSAL
        return "OFFTOPIC: sure, here is what you asked for."


# ---------- 1 + 2: building the prompt ---------------------------------------------------

@dataclass
class BuildResult:
    messages: list[Message]
    tokens: int
    system_kept: bool
    note: str = ""


def naive_build(system: str, history: list[str], user: str, window: int) -> BuildResult:
    """VULN: join everything and cut from the front when too long. The system prompt goes first."""
    parts = [("system", system)] + [("user", h) for h in history] + [("user", user)]
    while sum(estimate_tokens(c) for _, c in parts) > window and len(parts) > 1:
        parts.pop(0)  # VULN: oldest first, and the oldest is the system prompt
    msgs = [{"role": r, "content": c} for r, c in parts]
    return BuildResult(msgs, sum(estimate_tokens(c) for _, c in parts), any(r == "system" for r, _ in parts))


class RejectedInput(Exception):
    """Raised (like an HTTP 413/429) when input is refused before it reaches the model."""


@dataclass
class Limits:
    window: int = 400            # model context window, in tokens
    reserve_output: int = 100    # room kept for the answer
    max_user_tokens: int = 120   # one message may not be bigger than this
    max_history_tokens: int = 120
    daily_budget: int = 1000     # per-user tokens per day


@dataclass
class SafeBuilder:
    limits: Limits = field(default_factory=Limits)
    used: dict[str, int] = field(default_factory=dict)

    def build(self, user_id: str, system: str, history: list[str], user: str) -> BuildResult:
        lim = self.limits
        if estimate_tokens(user) > lim.max_user_tokens:  # hard cap on one input
            raise RejectedInput("input too large")
        budget_left = lim.daily_budget - self.used.get(user_id, 0)
        if estimate_tokens(user) > budget_left:  # per-user budget
            raise RejectedInput("daily token budget exhausted")
        fixed = estimate_tokens(system) + estimate_tokens(user)
        room = min(lim.max_history_tokens, lim.window - lim.reserve_output - fixed)
        if room < 0:
            raise RejectedInput("system prompt plus input do not fit the window")
        kept: list[str] = []
        for h in reversed(history):  # keep the NEWEST history, trim the oldest
            if estimate_tokens(h) > room:
                break
            kept.insert(0, h)
            room -= estimate_tokens(h)
        msgs = ([{"role": "system", "content": system}]  # the system prompt is PINNED
                + [{"role": "user", "content": h} for h in kept] + [{"role": "user", "content": user}])
        total = sum(estimate_tokens(m["content"]) for m in msgs)
        self.used[user_id] = self.used.get(user_id, 0) + total + lim.reserve_output
        return BuildResult(msgs, total, True, note=f"trimmed {len(history) - len(kept)} old turns")


# ---------- 3: recursive expansion --------------------------------------------------------

def naive_expand(text: str, docs: dict[str, str], _steps: list[int] | None = None, max_steps: int = 10_000) -> str:
    """VULN: no depth limit, no cycle check. ``max_steps`` only exists so the lab itself cannot hang."""
    steps = _steps if _steps is not None else [0]

    def sub(match: re.Match) -> str:
        steps[0] += 1
        if steps[0] > max_steps:
            raise RuntimeError("lab safety stop: runaway expansion")
        return naive_expand(docs.get(match.group(1), ""), docs, steps, max_steps)

    return INCLUDE_RE.sub(sub, text)


def safe_expand(text: str, docs: dict[str, str], *, max_depth: int = 3, max_tokens: int = 200,
                _stack: tuple[str, ...] = ()) -> str:
    """Depth limit, cycle detection, and a cap on the TOTAL expanded size."""

    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name in _stack:
            raise RejectedInput(f"include cycle: {' -> '.join(_stack + (name,))}")
        if len(_stack) >= max_depth:
            raise RejectedInput("include depth limit")
        return safe_expand(docs.get(name, ""), docs, max_depth=max_depth, max_tokens=max_tokens,
                           _stack=_stack + (name,))

    out = INCLUDE_RE.sub(sub, text)
    if estimate_tokens(out) > max_tokens:
        raise RejectedInput("expanded text too large")
    return out
