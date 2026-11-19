"""Trivy-style secret scanner: regex rules + keyword + entropy, allow rules and an ignore file. Run on FAKE secrets only."""

from __future__ import annotations

import fnmatch
import json
import math
import re
from collections import Counter

# Obviously fake values. Some match real-world *formats* so the rules can be exercised.
FIXTURE = {
    "config/app.env": "DB_HOST=db.example\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSTAGE=prod\n",
    "src/client.py": "token = 'ghp_" + "FAKE" * 9 + "'\nprint('hello')\n",
    "deploy/key.pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----\n",
    "src/settings.py": "SECRET_KEY = 'q9X7zLm2Rt8VbN4cHy6WpD1sKj3FgA0e'\nDEBUG = False\n",
    "tests/test_auth.py": "password = 'FAKE-test-password-1'  # test fixture\n",
    "README.md": "Set AWS_ACCESS_KEY_ID to your key id (looks like AKIAXXXXXXXXXXXXXXXX).\n",
}

RULES = [
    {"id": "aws-access-key-id", "category": "AWS", "title": "AWS Access Key ID", "severity": "CRITICAL", "regex": r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"},
    {"id": "github-pat", "category": "GitHub", "title": "GitHub personal access token", "severity": "CRITICAL", "regex": r"\bghp_[A-Za-z0-9]{36}\b"},
    {"id": "private-key", "category": "AsymmetricPrivateKey", "title": "Private key", "severity": "HIGH", "regex": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"},
    {"id": "generic-secret", "category": "Generic", "title": "High-entropy value assigned to a secret-like name", "severity": "MEDIUM",
     "regex": r"(?i)(secret|token|passwd|password|api[_-]?key)\w*\s*[=:]\s*['\"]([^'\"]{16,})['\"]", "entropy": 3.5, "group": 2},
]
ALLOW_PATHS = ["tests/*", "*.md"]


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def redact(s: str) -> str:
    return s[:4] + "*" * max(len(s) - 4, 4)


def scan_text(path: str, text: str, rules=RULES):
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule in rules:
            for m in re.finditer(rule["regex"], line):
                val = m.group(rule.get("group", 0))
                if "entropy" in rule and entropy(val) < rule["entropy"]:
                    continue
                out.append({"RuleID": rule["id"], "Category": rule["category"], "Severity": rule["severity"], "Title": rule["title"],
                            "StartLine": lineno, "Match": redact(val), "Target": path})
    return out


def scan_tree(files: dict, ignore_ids=(), allow_paths=ALLOW_PATHS):
    results = []
    for path, text in files.items():
        if any(fnmatch.fnmatch(path, g) for g in allow_paths):
            continue
        found = [f for f in scan_text(path, text) if f["RuleID"] not in ignore_ids]
        if found:
            results.append({"Target": path, "Class": "secret", "Secrets": found})
    return results


def exit_code(results, fail_on=("CRITICAL", "HIGH")) -> int:
    return 1 if any(s["Severity"] in fail_on for r in results for s in r["Secrets"]) else 0


def as_json(results) -> str:
    return json.dumps({"Results": results}, indent=2)
