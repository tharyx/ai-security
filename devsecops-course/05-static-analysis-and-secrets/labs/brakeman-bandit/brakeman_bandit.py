"""Normalise a Brakeman JSON report (Rails) and a Bandit-like run (Python) into one finding format.

One schema lets the pipeline gate, dedupe and report across languages: tool, rule, CWE, severity,
confidence, location and a line-independent fingerprint. The Bandit-like engine is the bandit_lite
framework from ../bandit-custom-checks.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path

from aisec_lab import load_lab_module

bl = load_lab_module(str(Path(__file__).resolve().parents[1] / "bandit-custom-checks" / "x.py"), "bandit_lite")

# Brakeman warning_type -> CWE (a small, hedged mapping; verify against the Brakeman docs).
BRAKEMAN_CWE = {"SQL Injection": 89, "Cross-Site Scripting": 79, "Command Injection": 78, "Redirect": 601,
                "Mass Assignment": 915, "File Access": 22, "Remote Code Execution": 94,
                "Cross-Site Request Forgery": 352}
BRAKEMAN_CONF = {"High": "HIGH", "Medium": "MEDIUM", "Weak": "LOW"}
# Brakeman reports no severity, only confidence. Derive severity from the weakness class (policy choice).
SEVERITY_BY_CWE = {89: "HIGH", 78: "HIGH", 94: "HIGH", 79: "MEDIUM", 22: "MEDIUM", 352: "MEDIUM", 601: "LOW", 915: "MEDIUM"}
RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class Finding:
    tool: str
    language: str
    rule: str
    title: str
    cwe: int | None
    severity: str
    confidence: str
    path: str
    line: int
    fingerprint: str

    @property
    def score(self) -> int:
        """Severity weighted by confidence: HIGH/HIGH=9 ... LOW/LOW=1."""
        return RANK[self.severity] * RANK[self.confidence]


def _fp(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:10]


def from_brakeman(path: Path) -> tuple[list[Finding], list[dict]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for w in data["warnings"]:
        cwe = BRAKEMAN_CWE.get(w["warning_type"])
        loc = w.get("location", {})
        where = loc.get("method") or loc.get("template") or ""
        out.append(Finding("brakeman", "ruby", w["check_name"], w["warning_type"], cwe,
                           SEVERITY_BY_CWE.get(cwe, "MEDIUM"), BRAKEMAN_CONF.get(w["confidence"], "LOW"),
                           w["file"], int(w["line"]), _fp("brakeman", w["warning_type"], w["file"], loc.get("class"), where)))
    return out, data.get("ignored_warnings", [])


def from_bandit_like(root: Path) -> list[Finding]:
    issues = bl.scan_path(root, [f for f in bl.load_checks(bl) if f._test_id != "B608"])
    out = []
    for i in issues:
        out.append(Finding("bandit-like", "python", i.test_id, i.text.rstrip("."), i.cwe, i.severity, i.confidence,
                           i.filename, i.lineno, _fp("bandit", i.test_id, i.filename, i.code)))
    return out


def merge(*lists: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in sorted((x for lst in lists for x in lst), key=lambda f: (-f.score, f.path, f.line)):
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            out.append(f)
    return out


def by_cwe(findings: list[Finding]) -> dict[int | None, list[Finding]]:
    out: dict[int | None, list[Finding]] = {}
    for f in findings:
        out.setdefault(f.cwe, []).append(f)
    return out


def gate(findings: list[Finding], min_score: int = 6, baseline: set[str] | None = None) -> int:
    """Fail on any NEW finding at or above min_score (severity x confidence). `baseline` holds accepted fingerprints."""
    baseline = baseline or set()
    return 1 if any(f.score >= min_score and f.fingerprint not in baseline for f in findings) else 0


def to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)
