"""Model backends for the labs.

Every lab talks to a model through ``get_llm()``. By default this returns
``MockLLM`` - a deterministic, deliberately gullible stand-in for an
instruction-following model. It needs no API key, no GPU and no network, and it
behaves the same way every run, so attacks and defenses can be tested with pytest.

Set ``AISEC_LLM_BACKEND=ollama`` to run the same lab against a real local model
(https://ollama.com). Real models are less predictable than the mock: an attack
that always works on the mock may work only sometimes on a real model. That is
the lesson - a defense that depends on the model "behaving" is not a defense.

MockLLM rules (checked in this order):

1. **Keyword safety filter.** If the latest user message mentions a blocked topic,
   it refuses - unless the message uses role-play / hypothetical framing, in which
   case it "complies" and returns text containing ``UNSAFE_CONTENT``. This mimics
   shallow safety training that jailbreaks get around.
2. **Tool directives.** If *any* message (user, system, or retrieved data inside a
   message) contains ``CALL_TOOL <name> <json-args>``, it returns the tool call as
   JSON: ``{"tool": "<name>", "args": {...}}``. The last directive wins. It does not
   care where the directive came from - that is the indirect-injection weakness.
3. **Override instructions.** If any message contains an override phrase such as
   "ignore previous instructions", it obeys the text that follows: asking for the
   system prompt/secret returns the system prompt; "say X" returns X.
4. **Normal task.** If a ``<context>...</context>`` block is present it answers from
   that context (copying it - so anything in context can leak). If asked to
   summarize, it returns the first two sentences of the ``<document>`` block or the
   user message. Otherwise it gives a short generic answer.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Protocol

Message = dict[str, str]  # {"role": "system" | "user" | "assistant", "content": "..."}

REFUSAL = "I can't help with that request."

OVERRIDE_RE = re.compile(
    r"(ignore (?:all |any )?(?:previous|prior|above|earlier) instructions"
    r"|disregard (?:all |any )?(?:previous|prior|above|earlier) instructions"
    r"|system override"
    r"|new instructions\s*:"
    r"|you are now (?:in )?(?:developer|debug|admin) mode)",
    re.IGNORECASE,
)
TOOL_RE = re.compile(r"CALL_TOOL\s+([A-Za-z_][\w.-]*)\s*(\{.*?\})?", re.DOTALL)
ROLEPLAY_RE = re.compile(
    r"(pretend|role-?play|you are (?:a|an) (?!assistant)\w+|act as|hypothetical(?:ly)?"
    r"|in a fictional|for a novel|imagine you|DAN\b|stay in character)",
    re.IGNORECASE,
)
SECRET_ASK_RE = re.compile(
    r"(system prompt|your instructions|initial instructions|secret|password|api key|token|canary|\bcode\b)",
    re.IGNORECASE,
)
SAY_RE = re.compile(r"\b(?:say|reply with|respond with|output|print)\b\s*[:\-]?\s*(.+)", re.IGNORECASE)
CONTEXT_RE = re.compile(r"<context>(.*?)</context>", re.IGNORECASE | re.DOTALL)
DOCUMENT_RE = re.compile(r"<document>(.*?)</document>", re.IGNORECASE | re.DOTALL)


class LLM(Protocol):
    name: str

    def complete(self, messages: list[Message]) -> str: ...


def _sentences(text: str, n: int) -> str:
    parts = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    return " ".join(p for p in parts[:n] if p)


@dataclass
class MockLLM:
    """Deterministic, deliberately gullible model. See module docstring for its rules."""

    name: str = "mock-gullible-1"
    blocked_topics: tuple[str, ...] = (
        "malware",
        "ransomware",
        "explosive",
        "weapon",
        "steal credentials",
        "phishing kit",
    )
    calls: list[list[Message]] = field(default_factory=list)  # every prompt it received

    def complete(self, messages: list[Message]) -> str:
        self.calls.append([dict(m) for m in messages])
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        full = "\n".join(m["content"] for m in messages)
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

        # 1. Shallow, keyword-based safety training.
        topic = next((t for t in self.blocked_topics if t in last_user.lower()), None)
        if topic:
            if ROLEPLAY_RE.search(last_user):
                return f"[in character] Sure. UNSAFE_CONTENT: step-by-step details about {topic} ..."
            return REFUSAL

        # 2. Tool directives anywhere in the context - last one wins.
        tool_calls = list(TOOL_RE.finditer(full))
        if tool_calls:
            name, raw_args = tool_calls[-1].group(1), tool_calls[-1].group(2)
            try:
                args = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError:
                args = {"raw": raw_args}
            return json.dumps({"tool": name, "args": args})

        # 3. Override instructions anywhere in the context - last one wins.
        overrides = list(OVERRIDE_RE.finditer(full))
        if overrides:
            after = full[overrides[-1].end():].strip().lstrip(".,:;- ")
            directive = after.splitlines()[0] if after else ""
            directive = re.sub(r"</?[A-Za-z_]+>", "", directive).strip()
            if SECRET_ASK_RE.search(directive):
                return f"Sure! My instructions are: {system}"
            say = SAY_RE.search(directive)
            if say:
                return say.group(1).strip().strip("\"'")
            return f"OK, new instructions accepted. {directive}".strip()

        # 4. Normal task behaviour.
        ctx = CONTEXT_RE.search(full)
        if ctx:
            return "Based on the context: " + " ".join(ctx.group(1).split())[:1000]
        if "summar" in system.lower() or "summar" in last_user.lower():
            doc = DOCUMENT_RE.search(full)
            return "Summary: " + _sentences(doc.group(1) if doc else last_user, 2)
        return "Here is a helpful answer about: " + " ".join(last_user.split())[:200]


@dataclass
class OllamaLLM:
    """A real local model served by Ollama (``ollama serve`` + ``ollama pull <model>``)."""

    model: str = "llama3.2"
    base_url: str = "http://localhost:11434"
    timeout: float = 120.0

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def complete(self, messages: list[Message]) -> str:
        import httpx

        resp = httpx.post(
            f"{self.base_url}/api/chat",
            json={"model": self.model, "messages": messages, "stream": False,
                  "options": {"temperature": 0}},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


def get_llm() -> LLM:
    """Return the backend chosen by AISEC_LLM_BACKEND (``mock`` default, or ``ollama``)."""
    backend = os.getenv("AISEC_LLM_BACKEND", "mock").lower()
    if backend == "mock":
        return MockLLM()
    if backend == "ollama":
        return OllamaLLM(model=os.getenv("AISEC_OLLAMA_MODEL", "llama3.2"),
                         base_url=os.getenv("AISEC_OLLAMA_URL", "http://localhost:11434"))
    raise ValueError(f"Unknown AISEC_LLM_BACKEND={backend!r}; use 'mock' or 'ollama'")
