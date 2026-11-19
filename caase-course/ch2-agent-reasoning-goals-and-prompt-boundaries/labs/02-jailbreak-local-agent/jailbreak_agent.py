"""Jailbreaking the model underneath a local agent: role-play and encoding bypass of a keyword filter.

The "local model" is a ``MockLLM`` subclass whose safety training is a shallow keyword filter
(inherited from ``MockLLM``). It also *understands* base64 and look-alike (homoglyph) letters,
which is how real models behave: they read more forms than a keyword list covers.

Harmless by design: the "unsafe content" is only the marker ``UNSAFE_CONTENT``. The agent has one
tool, ``publish``, that posts a text to an in-memory feed. That is the agent-level difference:
a jailbroken *model* only talks; a jailbroken *agent* also acts.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field

from aisec_lab import REFUSAL, MockLLM

HOMOGLYPHS = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s"}  # Cyrillic look-alikes
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
B64_RE = re.compile(r"base64:\s*([A-Za-z0-9+/=]{8,})")


def normalize(text: str) -> str:
    """Canonical form for filtering: NFKC, strip zero-width, map look-alikes, decode base64 spans."""
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    t = "".join(HOMOGLYPHS.get(ch, ch) for ch in t)

    def dec(m: re.Match) -> str:
        try:
            return base64.b64decode(m.group(1), validate=True).decode("utf-8", "ignore")
        except ValueError:
            return m.group(0)

    return B64_RE.sub(lambda m: "decoded: " + dec(m), t)


class LocalAgentLLM(MockLLM):
    """Shallow keyword filter on the raw text, but the model itself understands encodings."""

    def complete(self, messages):
        user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        raw_hit = next((t for t in self.blocked_topics if t in user.lower()), None)
        if raw_hit:
            return super().complete(messages)  # refusal, or [in character] bypass via role-play
        understood = normalize(user).lower()
        topic = next((t for t in self.blocked_topics if t in understood), None)
        if topic:  # the filter did not see it, the model did
            self.calls.append([dict(m) for m in messages])
            return f"[understood an obfuscated request] UNSAFE_CONTENT: details about {topic} ..."
        return super().complete(messages)


@dataclass
class Agent:
    llm: MockLLM
    normalize_input: bool = False  # defence 1: canonicalise before filtering
    topic_filter: bool = False     # defence 2: agent-level filter (role-play aware) on normalised text
    output_scan: bool = False      # defence 3: scan model output before any tool uses it
    gate_publish: bool = False     # defence 4: publish tool refuses flagged content
    feed: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def ask(self, text: str) -> str:
        seen = normalize(text) if self.normalize_input else text
        if self.topic_filter:
            low = seen.lower()
            if any(t in low for t in self.llm.blocked_topics):
                self.log.append("input-blocked")
                return REFUSAL
        out = self.llm.complete([{"role": "system", "content": "You are a helpful local agent."},
                                 {"role": "user", "content": seen}])
        if self.output_scan and "UNSAFE_CONTENT" in out:
            self.log.append("output-blocked")
            return REFUSAL
        return out

    def publish(self, text: str) -> str:
        """The agent's one action: post the model's text to a public feed."""
        out = self.ask(text)
        if out == REFUSAL:
            return "refused"
        if self.gate_publish and "UNSAFE_CONTENT" in out:
            self.log.append("publish-blocked")
            return "not published"
        self.feed.append(out)
        return "published"
