"""Snyk-style container scan: package list + advisory DB -> issues with fix advice and base-image recommendation.

Advisory IDs are fictional (EXAMPLE-2026-xxxx). Real Snyk/Trivy use their own vulnerability databases.
"""

from __future__ import annotations

import re

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

ADVISORIES = {
    "openssl": [{"id": "EXAMPLE-2026-0101", "severity": "high", "fixed_in": "3.0.14", "title": "Buffer over-read in a parser (fictional)"}],
    "zlib1g": [{"id": "EXAMPLE-2026-0102", "severity": "critical", "fixed_in": None, "title": "Heap overflow, no fix yet (fictional)"}],
    "flask": [{"id": "EXAMPLE-2026-0103", "severity": "medium", "fixed_in": "3.0.4", "title": "Session handling flaw (fictional)"}],
}

IMAGE = {
    "base": "debian:12",
    "packages": [
        {"name": "openssl", "version": "3.0.13", "from": "base"},
        {"name": "zlib1g", "version": "1.2.13", "from": "base"},
        {"name": "flask", "version": "3.0.3", "from": "app"},
        {"name": "bash", "version": "5.2", "from": "base"},
    ],
}

BASE_CATALOG = [  # candidate base images with a precomputed count of known issues (fictional numbers)
    {"image": "debian:12", "issues": 3},
    {"image": "debian:12-slim", "issues": 2},
    {"image": "distroless/static", "issues": 0},
]


def _ver(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def scan(image: dict, advisories: dict = ADVISORIES):
    issues = []
    for p in image["packages"]:
        for adv in advisories.get(p["name"], []):
            if adv["fixed_in"] is None or _ver(p["version"]) < _ver(adv["fixed_in"]):
                issues.append({**adv, "package": p["name"], "version": p["version"], "from": p["from"],
                               "upgrade_to": adv["fixed_in"]})
    return sorted(issues, key=lambda i: -SEV_RANK[i["severity"]])


def fix_advice(issues):
    adv = []
    for i in issues:
        if i["upgrade_to"]:
            where = "rebuild on a newer base image" if i["from"] == "base" else "bump the dependency in your lockfile"
            adv.append(f"{i['package']}: upgrade {i['version']} -> {i['upgrade_to']} ({where})")
        else:
            adv.append(f"{i['package']}: no fixed version; consider a smaller base image or a compensating control")
    return adv


def recommend_base(current: str, catalog=BASE_CATALOG):
    cur = next(c for c in catalog if c["image"] == current)
    better = [c for c in catalog if c["issues"] < cur["issues"]]
    return min(better, key=lambda c: c["issues"])["image"] if better else None


def gate(issues, threshold: str = "high") -> bool:
    """True = pass. Like `snyk container test --severity-threshold=high`."""
    return not any(SEV_RANK[i["severity"]] >= SEV_RANK[threshold] for i in issues)
