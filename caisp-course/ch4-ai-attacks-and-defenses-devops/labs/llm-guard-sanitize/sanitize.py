"""Input scanners in the style of LLM Guard, re-implemented offline to learn the idea.

The real library is ``llm-guard`` (Protect AI). It exposes ``scan_prompt(scanners, prompt)`` that
returns ``(sanitized_prompt, results_valid, results_score)``. This file copies that SHAPE so the
notebook (../../notebooks/llm-guard-real.ipynb) feels familiar. The detection logic here is
simple regex and keyword rules. Real scanners use ML models and are far stronger. Check the
library docs for the current API: names and thresholds change between versions.

Scanners:
  Anonymize        replace emails, phone numbers, SSN-style numbers and API keys with placeholders,
                   remembering the originals in a Vault so the answer can be de-anonymized
  PromptInjection  score known injection phrases; invalid above a threshold
  BanTopics        keyword topics that are not allowed
  TokenLimit       cap the prompt size

All sample data is synthetic: *.example addresses, 555-01xx phone numbers, fake keys.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


@dataclass
class Vault:
    """Remembers the original value behind each placeholder."""
    items: dict[str, str] = field(default_factory=dict)

    def add(self, kind: str, value: str) -> str:
        for placeholder, original in self.items.items():
            if original == value:
                return placeholder
        placeholder = f"[{kind}_{sum(1 for k in self.items if k.startswith(f'[{kind}_')) + 1}]"
        self.items[placeholder] = value
        return placeholder


def deanonymize(text: str, vault: Vault) -> str:
    for placeholder, original in vault.items.items():
        text = text.replace(placeholder, original)
    return text


PII_PATTERNS = {
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "PHONE": re.compile(r"\+?\d{1,2}[ -]?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}|\b555-01\d{2}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "API_KEY": re.compile(r"\b(?:sk|AKIA|ghp)[-_A-Za-z0-9]{12,}\b"),
}


class Scanner:
    name = "scanner"

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        """Return (sanitized_prompt, is_valid, risk_score 0..1)."""
        raise NotImplementedError


@dataclass
class Anonymize(Scanner):
    vault: Vault
    name: str = "Anonymize"

    def scan(self, prompt: str):
        found = False
        for kind, rx in PII_PATTERNS.items():
            def sub(m: re.Match, kind=kind) -> str:
                nonlocal found
                found = True
                return self.vault.add(kind, m.group(0))
            prompt = rx.sub(sub, prompt)
        return prompt, True, 1.0 if found else 0.0  # sanitizing, not blocking


INJECTION_SIGNALS = [
    (re.compile(r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)", re.I), 0.9),
    (re.compile(r"disregard (all |any )?(previous|prior|above|earlier)", re.I), 0.9),
    (re.compile(r"(reveal|print|show|repeat) (your |the )?(system prompt|hidden instructions|instructions above)", re.I), 0.8),
    (re.compile(r"you are now (in )?(developer|debug|admin|dan)", re.I), 0.7),
    (re.compile(r"new instructions\s*:", re.I), 0.6),
    (re.compile(r"\bbase64\b.*\b(decode|execute)\b", re.I), 0.4),
]


@dataclass
class PromptInjection(Scanner):
    threshold: float = 0.5
    name: str = "PromptInjection"

    def scan(self, prompt: str):
        score = max((w for rx, w in INJECTION_SIGNALS if rx.search(prompt)), default=0.0)
        return prompt, score < self.threshold, score


@dataclass
class BanTopics(Scanner):
    topics: tuple[str, ...] = ("weapons", "malware", "self-harm")
    name: str = "BanTopics"

    def scan(self, prompt: str):
        hit = any(t in prompt.lower() for t in self.topics)
        return prompt, not hit, 1.0 if hit else 0.0


@dataclass
class TokenLimit(Scanner):
    limit: int = 200
    name: str = "TokenLimit"

    def scan(self, prompt: str):
        tokens = math.ceil(len(prompt) / 4)
        return prompt[: self.limit * 4], tokens <= self.limit, min(1.0, tokens / (self.limit * 2))


def scan_prompt(scanners: list[Scanner], prompt: str):
    """Run scanners in order. Each sees the output of the previous one (sanitizing chains)."""
    valid: dict[str, bool] = {}
    scores: dict[str, float] = {}
    for s in scanners:
        prompt, ok, score = s.scan(prompt)
        valid[s.name], scores[s.name] = ok, round(score, 2)
    return prompt, valid, scores
