"""Pipeline design validator + blue/green and canary release simulators.

validate(spec) checks a web-app pipeline design against required security gates.
BlueGreen simulates: deploy to idle -> health check -> flip router -> post-flip check -> rollback.
Pure Python, offline. Nothing is deployed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

REQUIRED = ["secrets-scan", "sca", "sast", "build", "image-scan", "dast", "deploy-staging", "deploy-prod"]
SECURITY_GATES = {"secrets-scan", "sca", "sast", "image-scan", "dast", "sign"}
STRATEGIES = {"blue-green", "canary", "rolling"}
# (a, b) means: a must come BEFORE b
ORDER_RULES = [
    ("secrets-scan", "build"), ("sast", "build"), ("sca", "build"),
    ("build", "image-scan"), ("image-scan", "deploy-staging"),
    ("deploy-staging", "dast"), ("dast", "deploy-prod"),
    ("image-scan", "deploy-prod"), ("sign", "deploy-prod"),
]


@dataclass
class Issue:
    severity: str  # error | warning
    rule: str
    message: str


def load(text_or_path: str) -> dict:
    if "\n" in text_or_path:
        return yaml.safe_load(text_or_path)
    with open(text_or_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def validate(spec: dict) -> list:
    issues: list[Issue] = []
    stages = spec.get("stages") or []
    types = [s.get("type") for s in stages]
    pos = {t: i for i, t in enumerate(types)}

    for t in REQUIRED:
        if t not in pos:
            issues.append(Issue("error", "missing-gate", f"required stage type '{t}' is missing"))
    if "sign" not in pos:
        issues.append(Issue("warning", "missing-sign", "no 'sign' stage: unsigned images can be swapped"))
    for a, b in ORDER_RULES:
        if a in pos and b in pos and pos[a] > pos[b]:
            issues.append(Issue("error", "order", f"'{a}' must run before '{b}'"))
    for s in stages:
        if s.get("type") in SECURITY_GATES:
            if not s.get("blocking", False) or s.get("allow_failure"):
                issues.append(Issue("error", "not-blocking", f"gate '{s.get('id')}' must be blocking"))
            if s.get("type") != "sign" and not s.get("fail_on"):
                issues.append(Issue("warning", "no-threshold", f"gate '{s.get('id')}' has no fail_on threshold"))
    prod = next((s for s in stages if s.get("type") == "deploy-prod"), None)
    if prod:
        if prod.get("strategy") not in STRATEGIES:
            issues.append(Issue("error", "strategy", f"deploy-prod needs strategy in {sorted(STRATEGIES)}"))
        if prod.get("rollback") != "automatic":
            issues.append(Issue("error", "rollback", "deploy-prod needs rollback: automatic"))
        if not (prod.get("health_check") or {}).get("path"):
            issues.append(Issue("error", "health-check", "deploy-prod needs a health_check path"))
        if spec.get("mode") == "delivery" and prod.get("approval") != "manual":
            issues.append(Issue("error", "approval", "mode delivery needs approval: manual on deploy-prod"))
        if spec.get("mode") not in ("delivery", "deployment"):
            issues.append(Issue("error", "mode", "mode must be 'delivery' or 'deployment'"))
    if spec.get("branch") != "main":
        issues.append(Issue("warning", "branch", "production deploys should come from the protected main branch"))
    return issues


def errors(issues: list) -> list:
    return [i for i in issues if i.severity == "error"]


# ---------------------------------------------------------------- blue/green


@dataclass
class ReleaseResult:
    status: str  # released | aborted | rolled-back
    live: str
    events: list = field(default_factory=list)


class BlueGreen:
    """Two identical environments; a router points to one of them (the 'live' one)."""

    def __init__(self, live: str = "blue", version: str = "1.0.0"):
        if live not in ("blue", "green"):
            raise ValueError("live must be blue or green")
        self.live = live
        self.versions = {"blue": None, "green": None}
        self.versions[live] = version

    @property
    def idle(self) -> str:
        return "green" if self.live == "blue" else "blue"

    def release(self, version, health=lambda env, ver: True, post_flip=lambda ver: True, retries: int = 3):
        ev = []
        idle = self.idle
        self.versions[idle] = version
        ev.append(f"deploy {version} to idle env '{idle}' (live is still '{self.live}')")
        healthy = False
        for attempt in range(1, retries + 1):
            healthy = bool(health(idle, version))
            ev.append(f"health check {attempt}/{retries} on '{idle}': {'ok' if healthy else 'FAIL'}")
            if healthy:
                break
        if not healthy:
            self.versions[idle] = None
            ev.append(f"abort: users never left '{self.live}'")
            return ReleaseResult("aborted", self.live, ev)
        previous = self.live
        self.live = idle
        ev.append(f"flip router: live is now '{self.live}' ({version})")
        if not post_flip(version):
            self.live = previous
            ev.append(f"post-flip check FAILED: rollback, router back to '{previous}'")
            return ReleaseResult("rolled-back", self.live, ev)
        ev.append(f"post-flip check ok; keep '{previous}' warm for fast rollback")
        return ReleaseResult("released", self.live, ev)

    def rollback(self) -> str:
        """Manual rollback: flip back to the idle env if it still has a version."""
        if self.versions[self.idle] is None:
            raise RuntimeError("nothing to roll back to")
        self.live = self.idle
        return self.live


def canary_rollout(steps, error_rate_for, max_error: float = 0.01) -> dict:
    """Increase traffic share step by step; stop and roll back if the error rate is too high."""
    history = []
    for pct in steps:
        rate = error_rate_for(pct)
        history.append((pct, rate))
        if rate > max_error:
            return {"status": "rolled-back", "stopped_at": pct, "history": history}
    return {"status": "released", "stopped_at": None, "history": history}
