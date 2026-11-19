"""Find vulnerable components by inventory + advisory matching, and compute days exposed.

Offline and synthetic. No scanning of any real system.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# Patch SLAs in days, by severity. Example numbers: tune them to your own policy.
DEFAULT_SLA = {"critical": 2, "high": 15, "medium": 30, "low": 90}


def parse_version(v: str):
    """'2.3.31' -> (2, 3, 31). Non-numeric parts make the version unparseable (we say so, we do not guess)."""
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError as exc:
        raise ValueError(f"cannot parse version {v!r}") from exc


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_affected(version: str, ranges: list) -> bool:
    v = parse_version(version)
    return any(_cmp(parse_version(r["from"]), v) <= 0 and _cmp(v, parse_version(r["to"])) <= 0 for r in ranges)


@dataclass
class Finding:
    asset: str
    host: str
    component: str
    version: str
    advisory: str
    severity: str
    internet_facing: bool
    advisory_date: date
    days_exposed: int
    sla_days: int
    sla_breached: bool
    fixed_in: list
    owner: str | None


@dataclass
class Gap:
    asset: str
    host: str
    problem: str


def load(base: Path):
    inv = json.loads((base / "inventory.json").read_text())
    adv = json.loads((base / "advisories.json").read_text())
    return inv["assets"], adv["advisories"]


def find_vulnerabilities(assets, advisories, as_of: date, patched_on: dict | None = None, sla=None):
    """Match every inventory component against every advisory.

    days_exposed = (patched date, or as_of) - advisory publication date, for components still
    affected. `patched_on` maps asset id -> date the fix reached production (models the real fix).
    """
    sla = sla or DEFAULT_SLA
    findings, gaps = [], []
    for a in assets:
        if not a.get("components"):
            gaps.append(Gap(a["id"], a["host"], "no components recorded: this asset cannot be matched to any advisory"))
        if not a.get("owner"):
            gaps.append(Gap(a["id"], a["host"], "no owner: nobody will receive the patch ticket"))
        for c in a.get("components", []):
            for adv in advisories:
                if adv["component"] != c["name"]:
                    continue
                try:
                    hit = version_affected(c["version"], adv["affected"])
                except ValueError as exc:
                    gaps.append(Gap(a["id"], a["host"], str(exc)))
                    continue
                if not hit:
                    continue
                pub = date.fromisoformat(adv["published"])
                end = date.fromisoformat((patched_on or {}).get(a["id"], as_of.isoformat()))
                days = max((end - pub).days, 0)
                limit = sla[adv["severity"]]
                findings.append(Finding(a["id"], a["host"], c["name"], c["version"], adv["id"], adv["severity"],
                                        a["internet_facing"], pub, days, limit, days > limit,
                                        adv["fixed_in"], a.get("owner")))
    findings.sort(key=lambda f: (not f.internet_facing, -f.days_exposed))
    return findings, gaps


def timeline(advisory: dict, scan_missed: str, intrusion: str, discovery: str, as_of_patched: str):
    """The five dates that matter, with the gap between each pair."""
    d = {k: date.fromisoformat(v) for k, v in {
        "advisory_published": advisory["published"],
        "exploited_in_wild": advisory["exploited_in_wild_from"],
        "internal_scan_missed_it": scan_missed,
        "intrusion_began": intrusion,
        "breach_discovered": discovery,
        "fix_applied_(illustrative)": as_of_patched}.items()}
    keys = list(d)
    return [(k, d[k].isoformat(), (d[k] - d["advisory_published"]).days) for k in keys]


if __name__ == "__main__":
    base = Path(__file__).parent / "fixtures"
    assets, advs = load(base)
    fs, gs = find_vulnerabilities(assets, advs, date(2017, 5, 13))
    for f in fs:
        print(f)
    for g in gs:
        print(g)
