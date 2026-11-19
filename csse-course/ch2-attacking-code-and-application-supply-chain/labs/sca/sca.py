"""Mini Software Composition Analysis: lock file + local advisory database -> findings.

All package names and advisory ids in the fixtures are FICTIONAL. A real SCA tool (OSV-Scanner,
Trivy, Grype, pip-audit, npm audit, Dependabot) reads real databases such as OSV or GHSA.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


@dataclass
class Dep:
    name: str
    version: str
    direct: bool
    via: str | None


@dataclass
class Finding:
    advisory: str
    package: str
    version: str
    severity: str
    fixed_in: str | None
    direct: bool
    via: str | None
    summary: str


def parse_lock(text: str) -> list[Dep]:
    """Lines look like `name==1.2.3` (direct) or `name==1.2.3  # via parent` (transitive)."""
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        spec, _, comment = line.partition("#")
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([0-9][0-9A-Za-z.\-]*)", spec.strip())
        if not m:
            continue
        via = comment.strip()[4:].strip() if comment.strip().startswith("via ") else None
        deps.append(Dep(m.group(1).lower(), m.group(2), via is None, via))
    return deps


def is_affected(version: str, ranges: list[dict]) -> bool:
    """Each range is {introduced: 'x', fixed: 'y'}; affected if introduced <= v < fixed."""
    for r in ranges:
        lo = vkey(r.get("introduced", "0"))
        hi = vkey(r["fixed"]) if r.get("fixed") else None
        if vkey(version) >= lo and (hi is None or vkey(version) < hi):
            return True
    return False


def scan(deps: list[Dep], advisories: list[dict], ignore: dict[str, str] | None = None) -> list[Finding]:
    ignore = ignore or {}
    out = []
    for d in deps:
        for adv in advisories:
            if adv["package"].lower() != d.name or adv["id"] in ignore:
                continue
            if is_affected(d.version, adv["ranges"]):
                fixed = max((r["fixed"] for r in adv["ranges"] if r.get("fixed")), key=vkey, default=None)
                out.append(Finding(adv["id"], d.name, d.version, adv["severity"], fixed, d.direct, d.via, adv["summary"]))
    return sorted(out, key=lambda f: -SEV_ORDER[f.severity])


def exit_code(findings: list[Finding], fail_on: str = "high") -> int:
    return 1 if any(SEV_ORDER[f.severity] >= SEV_ORDER[fail_on] for f in findings) else 0


def load(lock: Path, db: Path) -> tuple[list[Dep], list[dict]]:
    return parse_lock(lock.read_text()), json.loads(db.read_text())
