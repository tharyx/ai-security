"""Presidio-style PII detection and anonymization, in plain stdlib Python.

Microsoft Presidio splits the job into an **analyzer** (recognizers find entities and
give each a confidence score) and an **anonymizer** (operators such as replace,
redact, mask or hash rewrite the text). This module copies that architecture in a
few lines so you can see how it works:

- a recognizer = regex pattern + base score + optional checksum validator + context words;
- a validator that fails drops the match (a 12-digit order number that fails the
  Verhoeff check is not an Aadhaar number);
- context words near a match raise its score (Presidio calls this context enhancement);
- overlapping matches are resolved by keeping the higher score, then the longer span;
- the anonymizer applies one operator per entity type and returns a report.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from aisec_lab import load_lab_module

data = load_lab_module(__file__, "ticket_data")

_PAN_ENTITY_CHARS = set("ABCFGHLJPT")  # 4th character of a PAN encodes the holder type


def _pan_valid(value: str) -> bool:
    return len(value) == 10 and value[3] in _PAN_ENTITY_CHARS


def _phone_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    return len(digits) == 10 and digits[0] in "6789"


@dataclass(frozen=True)
class Recognizer:
    entity: str
    pattern: re.Pattern
    base_score: float
    validator: Callable[[str], bool] | None = None
    context: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    entity: str
    start: int
    end: int
    score: float
    text: str


CONTEXT_BOOST = 0.35
CONTEXT_WINDOW = 5  # words before the match


def default_recognizers() -> list[Recognizer]:
    return [
        Recognizer("EMAIL_ADDRESS", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), 0.85, None, ("email", "mail")),
        Recognizer("IN_PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), 0.5, _pan_valid, ("pan", "income", "tax")),
        Recognizer("IN_AADHAAR", re.compile(r"(?<!\d)(?<!\d )[2-9]\d{3} ?\d{4} ?\d{4}(?! ?\d)"), 0.4,
                   data.verhoeff_valid, ("aadhaar", "uid", "uidai")),
        Recognizer("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 0.5, data.luhn_valid,
                   ("card", "visa", "credit", "debit")),
        Recognizer("PHONE_NUMBER", re.compile(r"(?:\+91[ -]?)?(?<!\d)[6-9]\d{4} ?\d{5}(?!\d)"), 0.3, _phone_valid,
                   ("call", "phone", "mobile", "whatsapp", "contact")),
    ]


class Analyzer:
    def __init__(self, recognizers: list[Recognizer] | None = None, threshold: float = 0.5,
                 use_validators: bool = True, use_context: bool = True) -> None:
        self.recognizers = recognizers or default_recognizers()
        self.threshold = threshold
        self.use_validators = use_validators
        self.use_context = use_context

    def analyze(self, text: str) -> list[Finding]:
        raw: list[Finding] = []
        for rec in self.recognizers:
            for m in rec.pattern.finditer(text):
                value = m.group(0)
                if self.use_validators and rec.validator and not rec.validator(value):
                    continue  # checksum / structure failed -> not this entity
                score = rec.base_score
                if self.use_validators and rec.validator:
                    score += 0.1
                if self.use_context and rec.context:
                    before = re.findall(r"[a-z]+", text[: m.start()].lower())[-CONTEXT_WINDOW:]
                    if any(w in rec.context for w in before):
                        score += CONTEXT_BOOST
                raw.append(Finding(rec.entity, m.start(), m.end(), min(score, 1.0), value))
        raw = [f for f in raw if f.score >= self.threshold]
        # overlap resolution: higher score first, then longer span
        raw.sort(key=lambda f: (-f.score, -(f.end - f.start)))
        kept: list[Finding] = []
        for f in raw:
            if all(f.end <= k.start or f.start >= k.end for k in kept):
                kept.append(f)
        return sorted(kept, key=lambda f: f.start)


# --------------------------------------------------------------------------- anonymizer
def op_replace(f: Finding) -> str:
    return f"<{f.entity}>"


def op_redact(f: Finding) -> str:
    return ""


def op_mask(f: Finding) -> str:
    digits = [c for c in f.text if c.isalnum()]
    return "*" * (len(digits) - 4) + "".join(digits[-4:])


def make_hash_op(salt: bytes) -> Callable[[Finding], str]:
    def op_hash(f: Finding) -> str:
        return f"<{f.entity}:" + hashlib.sha256(salt + f.text.encode()).hexdigest()[:8] + ">"
    return op_hash


OPERATORS = {"replace": op_replace, "redact": op_redact, "mask": op_mask}


@dataclass
class AnonymizeResult:
    text: str
    findings: list[Finding] = field(default_factory=list)


def anonymize(text: str, findings: list[Finding],
              operators: dict[str, Callable[[Finding], str]] | None = None,
              default: Callable[[Finding], str] = op_replace) -> AnonymizeResult:
    operators = operators or {}
    out, pos = [], 0
    for f in findings:
        out.append(text[pos:f.start])
        out.append(operators.get(f.entity, default)(f))
        pos = f.end
    out.append(text[pos:])
    return AnonymizeResult("".join(out), findings)


def redact_report(results: list[AnonymizeResult]) -> dict[str, int]:
    """Count entities found per type (the evidence you keep for an audit)."""
    return dict(Counter(f.entity for r in results for f in r.findings))
