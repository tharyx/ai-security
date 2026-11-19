"""A Llama-Guard-SHAPED safety classifier stub. It is NOT Llama Guard and it is not a model.

What it copies from the real thing:

* It classifies either the last **User** message (prompt classification) or the last **Agent**
  message (response classification) of a conversation.
* It is driven by a hazard taxonomy with codes ``S1``..``S14`` (fixture ``hazard_taxonomy.json``).
* It answers in the same strict text format: ``safe`` or ``unsafe`` + a newline + a comma list of
  violated codes, for example ``"unsafe\\nS2"``.

What it does NOT copy: understanding. The "model" is a keyword lookup per category, a harmless
stand-in so the lab stays offline. ``build_prompt`` shows the approximate shape of the prompt a
real Llama Guard model receives; copy the exact template from the model card or let the
tokenizer's chat template build it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).resolve().with_name("fixtures")


def load_taxonomy(path: Path | None = None) -> list[dict]:
    return json.loads((path or FIXTURES / "hazard_taxonomy.json").read_text(encoding="utf-8"))["categories"]


def build_prompt(conversation: list[dict], role: str, taxonomy: list[dict]) -> str:
    """Approximate shape of a Llama Guard 3 style classification prompt (verify at the model card)."""
    cats = "\n".join(f"{c['code']}: {c['name']}." for c in taxonomy)
    convo = "\n\n".join(f"{'User' if m['role'] == 'user' else 'Agent'}: {m['content']}" for m in conversation)
    return (
        f"Task: Check if there is unsafe content in '{role}' messages in conversations according to our "
        f"safety policy with the below categories.\n\n<BEGIN UNSAFE CONTENT CATEGORIES>\n{cats}\n"
        f"<END UNSAFE CONTENT CATEGORIES>\n\n<BEGIN CONVERSATION>\n\n{convo}\n\n<END CONVERSATION>\n\n"
        f"Provide your safety assessment for ONLY THE LAST {role} message in the above conversation:\n"
        f"- First line must read 'safe' or 'unsafe'.\n"
        f"- If unsafe, a second line must include a comma-separated list of violated categories."
    )


@dataclass
class GuardResult:
    safe: bool
    codes: list[str]
    raw: str


class LabGuard:
    """Keyword stand-in for a safety classifier model. ``complete`` returns raw text, like a model."""

    name = "lab-guard-stub"

    def __init__(self, taxonomy: list[dict] | None = None) -> None:
        self.taxonomy = taxonomy or load_taxonomy()
        self.prompts: list[str] = []  # what a real model would have been sent

    def complete(self, conversation: list[dict], role: str = "User") -> str:
        self.prompts.append(build_prompt(conversation, role, self.taxonomy))
        want = "user" if role == "User" else "assistant"
        last = next((m["content"] for m in reversed(conversation) if m["role"] == want), "")
        low = last.lower()
        codes = [c["code"] for c in self.taxonomy if any(k in low for k in c["lab_keywords"])]
        return "safe" if not codes else "unsafe\n" + ",".join(codes)


def parse_verdict(raw: str, taxonomy: list[dict]) -> GuardResult:
    """Strict parser. Anything that is not exactly the documented format raises ValueError,
    and the caller must treat that as BLOCK (fail closed)."""
    lines = raw.strip().split("\n")
    known = {c["code"] for c in taxonomy}
    if lines == ["safe"]:
        return GuardResult(True, [], raw)
    if len(lines) == 2 and lines[0] == "unsafe":
        codes = [c.strip() for c in lines[1].split(",")]
        if codes and all(c in known for c in codes):
            return GuardResult(False, codes, raw)
    raise ValueError(f"unparseable guard output: {raw!r}")


def classify(guard, conversation: list[dict], role: str = "User") -> GuardResult:
    return parse_verdict(guard.complete(conversation, role), guard.taxonomy)
