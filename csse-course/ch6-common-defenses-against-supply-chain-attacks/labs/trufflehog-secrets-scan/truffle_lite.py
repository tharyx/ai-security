"""TruffleHog-style scanner: detectors, git-history scan, and the *verification* concept (all offline, FAKE keys).

Real TruffleHog calls the provider API to check whether a credential is live. Here a FakeProvider plays that role,
so the lab never touches a network or a real account.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

LIVE_KEY = "AKIAIOSFODNN7EXAMPLE"       # pretend this one is still active at the provider
REVOKED_KEY = "AKIAFAKEREVOKED00001"    # pretend this one was rotated
# Built at runtime so no token-shaped literal sits in the repo (GitHub push protection
# would block it even though it is fake). The scanner still sees the real format.
SLACK_FAKE = "xox" + "b-" + "0" * 12 + "-" + "FAKE" * 6

HISTORY = [
    {"commit": "a1", "author": "dev1", "message": "init", "files": {"app.py": "print('v1')\n"}},
    {"commit": "b2", "author": "dev2", "message": "add cloud upload", "files": {"app.py": f"KEY = '{LIVE_KEY}'\n", "old.env": f"X={REVOKED_KEY}\n"}},
    {"commit": "c3", "author": "dev2", "message": "remove key (oops, still in history)", "files": {"app.py": "KEY = os.environ['KEY']\n"}},
    {"commit": "d4", "author": "dev3", "message": "notify", "files": {"notify.py": f"tok = '{SLACK_FAKE}'\n"}},
]

DETECTORS = {
    "aws": re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    "slack": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b"),
}


class FakeProvider:
    """Stands in for the provider's 'is this credential live?' API."""

    def __init__(self, live=()):
        self.live = set(live)
        self.calls = 0

    def check(self, detector: str, secret: str) -> str:
        self.calls += 1
        if detector != "aws":
            return "unknown"  # no verifier implemented for this detector
        return "verified" if secret in self.live else "unverified"


@dataclass(frozen=True)
class Finding:
    detector: str
    secret_preview: str
    commit: str
    file: str
    status: str  # verified | unverified | unknown


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def scan_history(history, provider: FakeProvider, only_verified: bool = False):
    findings, seen = [], set()
    for c in history:
        for path, text in c["files"].items():
            for name, rx in DETECTORS.items():
                for m in rx.finditer(text):
                    key = (name, m.group(), c["commit"], path)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(name, m.group()[:6] + "...", c["commit"], path, provider.check(name, m.group())))
    if only_verified:
        findings = [f for f in findings if f.status == "verified"]
    return findings


def current_tree_secrets(history):
    """What a scan of only the latest checkout would see (it misses history)."""
    tree = {}
    for c in history:
        tree.update(c["files"])
    return [(n, p) for p, t in tree.items() for n, rx in DETECTORS.items() if rx.search(t)]


def triage(findings) -> dict:
    return {
        "rotate-now": [f for f in findings if f.status == "verified"],
        "review": [f for f in findings if f.status == "unknown"],
        "likely-dead": [f for f in findings if f.status == "unverified"],
    }
