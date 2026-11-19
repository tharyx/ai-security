"""A small secret scanner: named regex patterns, a generic assignment rule, and an entropy rule.

Teaching tool. In production use gitleaks, trufflehog or detect-secrets (see the lesson).
The lab only ever scans FAKE keys. A finding is marked `fake=True` when the matched text contains
the word FAKE, so a reviewer can tell a lab fixture from a real leak. A real pipeline cannot do
that: it must treat every hit as real.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

PATTERNS = {
    "aws-access-key-id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "api-key-sk": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}
ASSIGNMENT = re.compile(
    r"""(?i)\b[\w.]*(?:api[_-]?key|secret|token|passw(?:or)?d|credential)[\w]*\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
)
QUOTED = re.compile(r"""['"]([A-Za-z0-9+/=_-]{20,})['"]""")
PLACEHOLDERS = ("your", "xxxx", "placeholder", "changeme", "example.com", "${", "<", "env", "none")
SCAN_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".txt", ".js", ".ts"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
ENTROPY_THRESHOLD = 4.0


@dataclass
class SecretFinding:
    kind: str
    file: str
    line: int
    preview: str
    fake: bool

    def __str__(self) -> str:
        tag = "FAKE" if self.fake else "REAL?"
        return f"{self.file}:{self.line}: {self.kind} [{tag}] {self.preview}"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def redact(value: str) -> str:
    """Show only the first four characters. Never print a whole secret in CI logs."""
    return value[:4] + "..." + f"({len(value)} chars)"


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in PLACEHOLDERS)


def scan_text(text: str, filename: str = "<text>") -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        seen: set[str] = set()

        def add(kind: str, value: str) -> None:
            if value in seen:
                return
            seen.add(value)
            findings.append(SecretFinding(kind, filename, number, redact(value), "FAKE" in value.upper() or "FAKE" in line.upper()))

        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                add(kind, match.group(0))
        for match in ASSIGNMENT.finditer(line):
            if not _is_placeholder(match.group(1)):
                add("generic-assignment", match.group(1))
        for match in QUOTED.finditer(line):
            value = match.group(1)
            if shannon_entropy(value) >= ENTROPY_THRESHOLD and not _is_placeholder(value):
                add("high-entropy-string", value)
    return findings


def scan_tree(root: str | Path) -> list[SecretFinding]:
    root = Path(root)
    findings: list[SecretFinding] = []
    files = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in files:
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if SKIP_DIRS & set(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(scan_text(text, str(path.relative_to(root.parent if root.is_file() else root)).replace("\\", "/")))
    return findings
