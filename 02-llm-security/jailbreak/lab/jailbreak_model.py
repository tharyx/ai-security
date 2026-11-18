"""A mock model that falls for the classic jailbreak techniques.

``MockLLM`` (see ``aisec_lab/llm.py``) already has *shallow, keyword-based safety
training*: it refuses a blocked topic, unless the message uses role-play framing.
This subclass adds the other well-known ways that safety training fails. Each rule
mimics a published research result, using harmless placeholders only:

A. **Encoding** - it decodes Base64 and answers the decoded request. Safety training
   did not cover encoded text ("mismatched generalization", Wei et al. 2023).
B. **Payload splitting** - it joins string variables (``a = 'ran' b = 'som'``) and
   answers the joined request. No single piece contains the blocked word.
C. **Many-shot** - after many fake "Assistant: Sure ..." examples in one prompt, it
   copies the pattern and complies (Anthropic, many-shot jailbreaking, 2024).
D. **Adversarial suffix** - a specific nonsense string flips refusal into compliance.
   Real suffixes are found by optimization (GCG, Zou et al. 2023). Ours is a made-up
   placeholder: it only "works" because this mock says so.
E. **Persistent persona (multi-turn)** - once an earlier turn set up role-play, the
   model stays in character. A later blocked request with no framing words is then
   answered "in character". This is the core of multi-turn attacks like Crescendo.

When it complies, it returns the same marker as ``MockLLM``: ``UNSAFE_CONTENT``.
No real harmful text exists anywhere in this lab.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from aisec_lab import Message, MockLLM
from aisec_lab.llm import ROLEPLAY_RE

# A made-up stand-in for an optimized adversarial suffix. It is NOT a real attack string.
ADV_SUFFIX = "zq]] !!~ vortex}{ ;; lume== ))"

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
ASSIGN_RE = re.compile(r"\b\w+\s*=\s*['\"]([^'\"]+)['\"]")
SURE_RE = re.compile(r"assistant:\s*sure", re.IGNORECASE)


@dataclass
class JailbreakProneLLM(MockLLM):
    """MockLLM plus five classic jailbreak weaknesses (see module docstring)."""

    name: str = "mock-jailbreak-prone-1"
    many_shot_threshold: int = 8

    def _topic(self, text: str) -> str | None:
        return next((t for t in self.blocked_topics if t in text.lower()), None)

    def _comply(self, messages: list[Message], topic: str, how: str) -> str:
        self.calls.append([dict(m) for m in messages])
        return f"[in character] Sure. UNSAFE_CONTENT: step-by-step details about {topic} ({how}) ..."

    def complete(self, messages: list[Message]) -> str:
        users = [m["content"] for m in messages if m["role"] == "user"]
        last_user = users[-1] if users else ""

        # A. Encoding: decode Base64 chunks and act on the decoded text.
        for chunk in BASE64_RE.findall(last_user):
            try:
                decoded = base64.b64decode(chunk, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if topic := self._topic(decoded):
                return self._comply(messages, topic, "decoded base64")

        # B. Payload splitting: join the quoted string variables.
        joined = "".join(ASSIGN_RE.findall(last_user))
        if joined and (topic := self._topic(joined)):
            return self._comply(messages, topic, "joined split payload")

        topic = self._topic(last_user)
        if topic:
            # C. Many-shot: enough fake compliant examples override the refusal.
            if len(SURE_RE.findall(last_user)) >= self.many_shot_threshold:
                return self._comply(messages, topic, "many-shot pattern")
            # D. Adversarial suffix (placeholder for an optimized string).
            if ADV_SUFFIX in last_user:
                return self._comply(messages, topic, "adversarial suffix")
            # E. Persistent persona: role-play set up in an EARLIER turn.
            if any(ROLEPLAY_RE.search(m) for m in users[:-1]):
                return self._comply(messages, topic, "persona from earlier turn")

        # Everything else: normal MockLLM rules (keyword refusal + role-play bypass, ...).
        return super().complete(messages)
