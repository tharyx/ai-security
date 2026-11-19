"""Shared helpers for the SCA labs: an OSV-format advisory database, version maths, gates, ignores.

All advisories, package names and ids in this chapter are FICTIONAL (DSO-OSV-nnnn).
OSV (osv.dev) records have `affected[].package`, `affected[].ranges[].events` with
introduced / fixed / last_affected, plus free `database_specific` data (we put severity there,
as GitHub advisories do). Verify the real schema at ossf.github.io/osv-schema.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ------------------------------------------------------------------ versions

def vkey(v: str) -> tuple:
    """Sortable key. Numeric, not string, compare: 1.10.0 > 1.9.0. A pre-release sorts below its release."""
    m = re.match(r"^[vV]?(\d+(?:\.\d+)*)(.*)$", v.strip())
    if not m:
        return ((0,), 0, v)
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    suffix = m.group(2).lstrip("-.+")
    return (tuple(nums), 0 if suffix else 1, suffix)


def in_ranges(version: str, ranges: list[dict]) -> bool:
    """OSV range logic: affected from `introduced` (inclusive) until `fixed` (exclusive) or last_affected."""
    v = vkey(version)
    for rng in ranges:
        affected = False
        for ev in rng.get("events", []):
            if "introduced" in ev:
                if ev["introduced"] == "0" or v >= vkey(ev["introduced"]):
                    affected = True
            elif "fixed" in ev:
                if v >= vkey(ev["fixed"]):
                    affected = False
            elif "last_affected" in ev:
                if v > vkey(ev["last_affected"]):
                    affected = False
        if affected:
            return True
    return False


def fixed_in(ranges: list[dict], version: str) -> str | None:
    """First `fixed` event above the installed version, or None when nothing is fixed yet."""
    v = vkey(version)
    fixes = [ev["fixed"] for rng in ranges for ev in rng.get("events", []) if "fixed" in ev and vkey(ev["fixed"]) > v]
    return min(fixes, key=vkey) if fixes else None


def fix_is_breaking(declared_range: str, fixed: str | None) -> bool | None:
    """Is the fix outside what a caret or tilde range allows? None when there is no fix."""
    if not fixed:
        return None
    m = re.match(r"^([\^~]?)(\d+)\.(\d+)", declared_range.strip())
    if not m:
        return True
    op, major, minor = m.group(1), int(m.group(2)), int(m.group(3))
    fk = vkey(fixed)[0]
    fmajor, fminor = fk[0], (fk[1] if len(fk) > 1 else 0)
    if op == "~":
        return (fmajor, fminor) != (major, minor)
    if op == "^" and major == 0:
        return (fmajor, fminor) != (major, minor)
    return fmajor != major


# ------------------------------------------------------------------ database

def load_db(path: Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def severity(rec: dict) -> str:
    return rec.get("database_specific", {}).get("severity", "MEDIUM").upper()


def cvss(rec: dict) -> float:
    return float(rec.get("database_specific", {}).get("cvss", 0.0))


def match_package(db: list[dict], ecosystem: str, name: str, version: str) -> list[tuple[dict, dict]]:
    """Exact (ecosystem, name) match, then version range. Returns (record, affected-entry) pairs."""
    hits = []
    for rec in db:
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") == ecosystem and pkg.get("name").lower() == name.lower():
                if in_ranges(version, aff.get("ranges", [])):
                    hits.append((rec, aff))
    return hits


@dataclass
class Finding:
    advisory: str
    ecosystem: str
    package: str
    version: str
    severity: str
    cvss: float
    summary: str
    fixed: str | None = None
    direct: bool = True
    dev: bool = False
    path: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    note: str = ""
    source: str = ""          # which scanner style produced it


def make_finding(rec: dict, aff: dict, ecosystem: str, name: str, version: str, **kw) -> Finding:
    return Finding(rec["id"], ecosystem, name, version, severity(rec), cvss(rec), rec.get("summary", ""),
                   fixed_in(aff.get("ranges", []), version),
                   cwes=rec.get("database_specific", {}).get("cwe_ids", []), **kw)


def sort_findings(fs: list[Finding]) -> list[Finding]:
    return sorted(fs, key=lambda f: (-RANK.get(f.severity, 0), -f.cvss, f.package, f.advisory))


# ------------------------------------------------------------------ ignores and gate

def apply_ignores(findings: list[Finding], ignores: list[dict], today: date):
    """Return (kept, suppressed, warnings). An ignore needs id, reason and a future expiry date."""
    kept, suppressed, warnings = [], [], []
    valid = []
    for ig in ignores:
        if not ig.get("reason"):
            warnings.append(f"ignore for {ig.get('id')} rejected: no reason")
        elif not ig.get("expires"):
            warnings.append(f"ignore for {ig.get('id')} rejected: no expiry date")
        elif date.fromisoformat(ig["expires"]) < today:
            warnings.append(f"ignore for {ig['id']} EXPIRED on {ig['expires']}: finding is active again")
        else:
            valid.append(ig)
    for f in findings:
        hit = next((ig for ig in valid if ig["id"] == f.advisory and ig.get("package", f.package) == f.package), None)
        (suppressed if hit else kept).append(f)
    return kept, suppressed, warnings


def gate(findings: list[Finding], fail_on: str = "HIGH", fail_cvss: float | None = None,
         max_findings: int | None = None) -> int:
    """Break-build rules. Fail when any finding is at or above `fail_on`, or CVSS >= `fail_cvss`,
    or the total count exceeds `max_findings`."""
    floor = RANK[fail_on.upper()]
    if any(RANK.get(f.severity, 0) >= floor for f in findings):
        return 1
    if fail_cvss is not None and any(f.cvss >= fail_cvss for f in findings):
        return 1
    if max_findings is not None and len(findings) > max_findings:
        return 1
    return 0


def render(findings: list[Finding]) -> str:
    out = []
    for f in findings:
        where = "direct" if f.direct else "via " + " > ".join(f.path[:-1]) if f.path else "transitive"
        dev = " dev" if f.dev else ""
        out.append(f"[{f.severity:8} {f.cvss:>4}] {f.advisory}  {f.package}@{f.version} ({where}{dev})  "
                   f"fix: {f.fixed or 'none'}  {f.summary}" + (f"  NOTE: {f.note}" if f.note else ""))
    return "\n".join(out)
