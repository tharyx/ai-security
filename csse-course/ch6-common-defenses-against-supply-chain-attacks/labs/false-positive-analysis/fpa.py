"""False Positive Analysis workflow: triage findings, keep a suppression file with justification and expiry."""

from __future__ import annotations

import hashlib
from datetime import date, timedelta

import yaml

FINDINGS = [
    {"tool": "secrets", "rule": "generic-secret", "path": "tests/fixtures/auth.py", "line": 4, "match": "password = 'FAKE-test-password-1'", "severity": "MEDIUM"},
    {"tool": "secrets", "rule": "aws-access-key-id", "path": "config/prod.env", "line": 2, "match": "AKIAIOSFODNN7EXAMPLE", "severity": "CRITICAL"},
    {"tool": "sast", "rule": "subprocess-shell-true", "path": "build/make_docs.py", "line": 18, "match": "subprocess.run(cmd, shell=True)", "severity": "HIGH"},
    {"tool": "sca", "rule": "EXAMPLE-2026-0001", "path": "requirements.txt", "line": 7, "match": "imagelib==1.2.0", "severity": "HIGH"},
    {"tool": "sast", "rule": "md5-usage", "path": "src/cache_keys.py", "line": 30, "match": "hashlib.md5(key)", "severity": "LOW"},
]

SUPPRESSIONS_YAML = """\
suppressions:
  - id: SUP-1
    rule: generic-secret
    path: tests/fixtures/*
    justification: "Test fixture with an obviously fake value; reviewed by security on 2026-03-01."
    owner: team-auth
    expires: 2027-03-01
  - id: SUP-2
    rule: subprocess-shell-true
    path: build/make_docs.py
    justification: "Command built from constants only; script runs in the docs build, never on user input."
    owner: team-docs
    expires: 2026-06-01
  - id: SUP-3
    rule: "*"
    path: "*"
    justification: "too noisy"
    owner: someone
    expires: 2030-01-01
  - id: SUP-4
    rule: md5-usage
    path: src/cache_keys.py
    owner: team-core
    expires: 2026-12-31
"""


def fingerprint(f: dict) -> str:
    return hashlib.sha256(f"{f['rule']}|{f['path']}|{f['match'].strip()}".encode()).hexdigest()[:12]


def load_suppressions(text: str):
    return yaml.safe_load(text)["suppressions"]


def validate_suppression(s: dict, today: date, max_days: int = 365):
    """Return a list of problems that make a suppression unacceptable."""
    problems = []
    if not str(s.get("justification", "")).strip():
        problems.append("missing justification")
    elif len(s["justification"].split()) < 5:
        problems.append("justification too short to be reviewable")
    if s.get("rule") == "*" or s.get("path") == "*":
        problems.append("too broad (wildcard rule or path)")
    if not s.get("owner"):
        problems.append("missing owner")
    exp = s.get("expires")
    if not exp:
        problems.append("missing expiry")
    elif exp - today > timedelta(days=max_days):
        problems.append(f"expiry more than {max_days} days away")
    return problems


def _matches(s: dict, f: dict) -> bool:
    import fnmatch
    return s["rule"] == f["rule"] and fnmatch.fnmatch(f["path"], s["path"])


def triage(findings, suppressions, today: date):
    """Split findings into active / suppressed, and explain every suppression decision."""
    active, suppressed, notes = [], [], []
    for f in findings:
        decision = None
        for s in suppressions:
            if not _matches(s, f):
                continue
            problems = validate_suppression(s, today)
            if s.get("expires") and s["expires"] < today:
                notes.append(f"{s['id']} expired on {s['expires']}: finding {f['rule']} re-activated")
            elif problems:
                notes.append(f"{s['id']} ignored: {', '.join(problems)}")
            else:
                decision = s
                break
        (suppressed if decision else active).append({**f, "fingerprint": fingerprint(f), **({"suppressed_by": decision["id"]} if decision else {})})
    return {"active": active, "suppressed": suppressed, "notes": notes}


def metrics(result) -> dict:
    total = len(result["active"]) + len(result["suppressed"])
    return {"total": total, "suppressed": len(result["suppressed"]),
            "fp_rate": round(len(result["suppressed"]) / total, 2) if total else 0.0}
