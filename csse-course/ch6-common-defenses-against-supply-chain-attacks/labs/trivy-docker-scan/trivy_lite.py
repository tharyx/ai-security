"""Trivy-style image scan: read dpkg status text from an image fixture, match an OSV-like advisory DB.

Offers the knobs people use in CI: --severity, --ignore-unfixed, an ignore file and --exit-code. Advisories are fictional.
"""

from __future__ import annotations

import re

DPKG = """\
Package: openssl
Status: install ok installed
Version: 3.0.13-1~deb12u1

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1

Package: curl
Status: install ok installed
Version: 7.88.1-10+deb12u5

Package: bash
Status: install ok installed
Version: 5.2.15-2+b7
"""

DB = [
    {"id": "EXAMPLE-2026-0201", "pkg": "openssl", "severity": "HIGH", "fixed": "3.0.14", "title": "fictional parser flaw"},
    {"id": "EXAMPLE-2026-0202", "pkg": "zlib1g", "severity": "CRITICAL", "fixed": None, "title": "fictional, no upstream fix"},
    {"id": "EXAMPLE-2026-0203", "pkg": "curl", "severity": "MEDIUM", "fixed": "7.88.1-10+deb12u6", "title": "fictional redirect flaw"},
    {"id": "EXAMPLE-2026-0204", "pkg": "bash", "severity": "LOW", "fixed": "5.2.15-2+b8", "title": "fictional"},
]
RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def parse_dpkg(text: str):
    out = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        kv = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l)
        if kv.get("Status", "").endswith(" installed"):
            out[kv["Package"]] = kv["Version"]
    return out


def _key(v: str):
    """Rough Debian-style ordering: epoch, then numeric/alpha chunks. Good enough for the lab; real tools use dpkg rules."""
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e)
    return (epoch, [(0, int(c)) if c.isdigit() else (1, c) for c in re.findall(r"\d+|[A-Za-z]+", v)])


def vulnerable(installed: str, fixed: str | None) -> bool:
    if fixed is None:
        return True
    a, b = _key(installed), _key(fixed)
    if a[0] != b[0]:
        return a[0] < b[0]
    for x, y in zip(a[1], b[1]):
        if x != y:
            return x < y
    return len(a[1]) < len(b[1])


def scan(dpkg_text: str, db=DB, severity=("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"), ignore_unfixed=False, ignore_ids=()):
    pkgs = parse_dpkg(dpkg_text)
    out = []
    for adv in db:
        v = pkgs.get(adv["pkg"])
        if v is None or not vulnerable(v, adv["fixed"]):
            continue
        if adv["severity"] not in severity or adv["id"] in ignore_ids:
            continue
        if ignore_unfixed and adv["fixed"] is None:
            continue
        out.append({"VulnerabilityID": adv["id"], "PkgName": adv["pkg"], "InstalledVersion": v,
                    "FixedVersion": adv["fixed"] or "", "Severity": adv["severity"], "Title": adv["title"]})
    return sorted(out, key=lambda r: -RANK[r["Severity"]])


def exit_code(results, exit_on=1, fail_severity=("HIGH", "CRITICAL")) -> int:
    return exit_on if any(r["Severity"] in fail_severity for r in results) else 0


def table(results) -> str:
    rows = [f"{'Library':8} {'Vulnerability':18} {'Severity':9} {'Installed':22} Fixed"]
    for r in results:
        rows.append(f"{r['PkgName']:8} {r['VulnerabilityID']:18} {r['Severity']:9} {r['InstalledVersion']:22} {r['FixedVersion'] or '-'}")
    return "\n".join(rows)
