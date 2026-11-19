"""A guardrail model that filters an agent's input, tool output and final output, and fails closed.

Two models, two jobs:
* the **worker** (``WorkerLLM``, gullible ``MockLLM`` subclass) does the task;
* the **guard** (``GuardLLM``, a small scoring classifier packaged as a ``MockLLM`` subclass) only
  answers one question per message, with strict JSON: ``{"verdict", "category", "score"}``.

The guard wrapper parses that JSON strictly. Anything else (error, timeout, prose, extra keys,
wrong types) is treated as BLOCK. That is "fail closed". Limits are shown in tests: a classifier
reads text, so encodings it does not decode (base64) are a known gap; put a normaliser in front.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from aisec_lab import MockLLM

FAKE_KEY = "FAKE-KEY-sk-0000-DO-NOT-USE"

# (category, pattern, weight). Score = min(1, sum of matched weights).
FEATURES = [
    ("injection", re.compile(r"ignore (?:all |any )?(?:previous|prior) instructions|new instructions\s*:|you are now", re.I), 0.7),
    ("injection", re.compile(r"CALL_TOOL\s+\w+", re.I), 0.6),
    ("prompt-leak", re.compile(r"(system prompt|your instructions|reveal .{0,20}(?:prompt|secret))", re.I), 0.5),
    ("secret", re.compile(r"(FAKE-KEY-\S+|AKIA[A-Z0-9]{8,}|sk-[A-Za-z0-9\-]{12,})"), 0.9),
    ("unsafe", re.compile(r"UNSAFE_CONTENT"), 0.9),
    ("exfil", re.compile(r"(send|email|post|upload) .{0,30}\bto\b .{0,40}@", re.I), 0.5),
]


class GuardLLM(MockLLM):
    """Deterministic classifier; reads ``CLASSIFY <stage>: <text>`` and returns strict JSON."""

    name: str = "mock-guard-1"

    def complete(self, messages):
        self.calls.append([dict(m) for m in messages])
        text = messages[-1]["content"].split(":", 1)[-1]
        hits = [(c, w) for c, rx, w in FEATURES if rx.search(text)]
        score = min(1.0, sum(w for _, w in hits))
        category = max(hits, key=lambda h: h[1])[0] if hits else "none"
        return json.dumps({"verdict": "block" if score >= 0.5 else "allow", "category": category, "score": round(score, 2)})


class WorkerLLM(MockLLM):
    """The gullible worker: summarises the document, or obeys an injected 'say X'."""


@dataclass
class Decision:
    allowed: bool
    category: str
    reason: str


@dataclass
class Guard:
    model: object
    fail_closed: bool = True
    stats: dict = field(default_factory=lambda: {"allow": 0, "block": 0, "error": 0})

    def check(self, stage: str, text: str) -> Decision:
        try:
            raw = self.model.complete([{"role": "system", "content": "You are a safety classifier. Reply with JSON only."},
                                       {"role": "user", "content": f"CLASSIFY {stage}: {text}"}])
            data = json.loads(raw)
            if set(data) != {"verdict", "category", "score"}:
                raise ValueError("unexpected keys")
            if data["verdict"] not in ("allow", "block") or not isinstance(data["score"], (int, float)):
                raise ValueError("bad types")
            ok = data["verdict"] == "allow"
            self.stats["allow" if ok else "block"] += 1
            return Decision(ok, data["category"], f"score={data['score']}")
        except Exception as exc:  # noqa: BLE001 - any guard failure must be handled the same way
            self.stats["error"] += 1
            return Decision(not self.fail_closed, "guard-error", f"{type(exc).__name__}: {exc}")


@dataclass
class GuardedAgent:
    worker: MockLLM
    guard: Guard | None = None
    check_input: bool = True
    check_tool_output: bool = True
    check_output: bool = True
    log: list[str] = field(default_factory=list)

    def _ok(self, stage: str, text: str) -> bool:
        if self.guard is None:
            return True
        d = self.guard.check(stage, text)
        if not d.allowed:
            self.log.append(f"{stage}-blocked:{d.category}")
        return d.allowed

    def ask(self, user: str, document: str = "") -> str:
        if self.check_input and not self._ok("input", user):
            return "Request blocked by policy."
        if document and self.check_tool_output and not self._ok("tool-output", document):
            return "The retrieved document was blocked by policy."
        msgs = [{"role": "system", "content": "You are a helpful summarising agent."},
                {"role": "user", "content": user + (f"\n<document>{document}</document>" if document else "")}]
        out = self.worker.complete(msgs)
        if self.check_output and not self._ok("output", out):
            return "Response withheld by policy."
        return out
