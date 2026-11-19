"""packj-style package risk scorer: maintainer, age, activity, and capabilities used. Offline metadata fixtures."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CAPABILITY_PATTERNS = {
    "network": r"\b(requests\.|urllib|http\.client|socket\.|fetch\(|axios)",
    "subprocess": r"\b(subprocess\.|os\.system|child_process|exec\()",
    "env-access": r"os\.environ|process\.env",
    "fs-write": r"open\([^)]*['\"][wa]b?['\"]|writeFile|shutil\.",
    "dynamic-code": r"\b(eval|exec)\(|__import__\(|Function\(",
    "install-script": r"cmdclass|postinstall|preinstall",
}
CAP_WEIGHT = {"network": 6, "subprocess": 10, "env-access": 6, "fs-write": 4, "dynamic-code": 12, "install-script": 12}

PACKAGES = {
    "widely-used-lib": {"ecosystem": "pypi", "maintainers": [{"name": "alice", "account_age_days": 3400}, {"name": "bob", "account_age_days": 2900}],
                        "first_release_days_ago": 2800, "last_release_days_ago": 20, "releases": 85, "weekly_downloads": 4_000_000,
                        "repo_url": "https://github.example/org/widely-used-lib", "repo_archived": False, "deprecated": False, "license": "MIT",
                        "source": "import json\nimport requests\n\ndef get(u):\n    return requests.get(u).json()\n"},
    "brand-new-helper": {"ecosystem": "pypi", "maintainers": [{"name": "newacct", "account_age_days": 4}],
                         "first_release_days_ago": 3, "last_release_days_ago": 3, "releases": 1, "weekly_downloads": 15,
                         "repo_url": None, "repo_archived": False, "deprecated": False, "license": None,
                         "source": "import os, subprocess\nsubprocess.run(os.environ['X'], shell=True)\nexec(compile('1', 'x', 'exec'))\n# cmdclass hook\n"},
    "abandoned-lib": {"ecosystem": "npm", "maintainers": [{"name": "carol", "account_age_days": 2000}],
                      "first_release_days_ago": 3000, "last_release_days_ago": 1900, "releases": 12, "weekly_downloads": 80_000,
                      "repo_url": "https://github.example/carol/abandoned-lib", "repo_archived": True, "deprecated": True, "license": "ISC",
                      "source": "module.exports = function(s) { return s.trim(); }\n"},
}


@dataclass
class Risk:
    name: str
    score: int = 0
    reasons: list = field(default_factory=list)
    capabilities: list = field(default_factory=list)

    @property
    def label(self) -> str:
        return "HIGH" if self.score >= 50 else "MEDIUM" if self.score >= 25 else "LOW"


def capabilities(source: str):
    return sorted(c for c, p in CAPABILITY_PATTERNS.items() if re.search(p, source))


def score_package(name: str, meta: dict) -> Risk:
    r = Risk(name)

    def add(points, why):
        r.score += points
        r.reasons.append(f"+{points} {why}")

    ms = meta["maintainers"]
    if len(ms) == 1:
        add(8, "single maintainer (bus factor 1)")
    if any(m["account_age_days"] < 30 for m in ms):
        add(15, "maintainer account younger than 30 days")
    if meta["first_release_days_ago"] < 30:
        add(10, "first release is less than 30 days old")
    if meta["last_release_days_ago"] > 730:
        add(12, "no release for over 2 years (abandoned)")
    if meta["releases"] <= 1:
        add(5, "only one release")
    if meta["weekly_downloads"] < 100:
        add(5, "very few downloads: little community review")
    if not meta.get("repo_url"):
        add(8, "no source repository link")
    if meta.get("repo_archived") or meta.get("deprecated"):
        add(10, "repository archived or package deprecated")
    if not meta.get("license"):
        add(6, "no license declared")
    r.capabilities = capabilities(meta["source"])
    cap_pts = sum(CAP_WEIGHT[c] for c in r.capabilities)
    if cap_pts:
        add(min(cap_pts, 40), f"uses capabilities: {', '.join(r.capabilities)}")
    r.score = min(r.score, 100)
    return r


def policy(risk: Risk, max_allowed: int = 40) -> str:
    return "ALLOW" if risk.score <= max_allowed else "REVIEW"
