"""bomber-style SBOM vulnerability scanner against a LOCAL OSV-format database. Offline; advisories are fictional."""

from __future__ import annotations

import re

SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [
        {"name": "imagelib", "version": "1.2.0", "purl": "pkg:pypi/imagelib@1.2.0"},
        {"name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1"},
        {"name": "left-padz", "version": "2.1.0", "purl": "pkg:npm/left-padz@2.1.0"},
        {"name": "flask", "version": "3.0.3", "purl": "pkg:pypi/flask@3.0.3"},
        {"name": "mystery", "version": "9.9.9"},  # no purl: cannot be matched reliably
    ],
}

OSV_DB = [
    {"id": "EXAMPLE-OSV-0001", "aliases": ["CVE-2099-0001"], "summary": "fictional image parsing flaw",
     "database_specific": {"severity": "HIGH"},
     "affected": [{"package": {"ecosystem": "PyPI", "name": "imagelib"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}]}]},
    {"id": "EXAMPLE-OSV-0002", "aliases": [], "summary": "fictional qs-style flaw",
     "database_specific": {"severity": "CRITICAL"},
     "affected": [{"package": {"ecosystem": "npm", "name": "express"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.19.2"}]}]}]},
    {"id": "EXAMPLE-OSV-0003", "aliases": [], "summary": "fictional, version 1.x only",
     "database_specific": {"severity": "MEDIUM"},
     "affected": [{"package": {"ecosystem": "npm", "name": "left-padz"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
]
RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ECO = {"pypi": "PyPI", "npm": "npm"}


def _v(s):
    return tuple(int(x) for x in re.findall(r"\d+", s))


def parse_purl(purl: str):
    m = re.fullmatch(r"pkg:([a-z]+)/(?:[^/@]+/)?([^@/]+)@(.+)", purl)
    return (ECO.get(m.group(1), m.group(1)), m.group(2), m.group(3)) if m else None


def in_range(version: str, events: list) -> bool:
    introduced, fixed = None, None
    for e in events:
        introduced = e.get("introduced", introduced)
        fixed = e.get("fixed", fixed)
    after_intro = introduced is None or introduced == "0" or _v(version) >= _v(introduced)
    return after_intro and (fixed is None or _v(version) < _v(fixed))


def scan(sbom: dict, db=OSV_DB, ignore_ids=()):
    results, unmatched = [], []
    for c in sbom["components"]:
        p = parse_purl(c.get("purl", ""))
        if not p:
            unmatched.append(c["name"])
            continue
        eco, name, ver = p
        for adv in db:
            if adv["id"] in ignore_ids or (set(adv["aliases"]) & set(ignore_ids)):
                continue
            for aff in adv["affected"]:
                if aff["package"]["ecosystem"] == eco and aff["package"]["name"] == name:
                    for rng in aff["ranges"]:
                        if in_range(ver, rng["events"]):
                            fixed = next((e["fixed"] for e in rng["events"] if "fixed" in e), None)
                            results.append({"package": f"{name}@{ver}", "id": adv["id"], "severity": adv["database_specific"]["severity"],
                                            "fixed": fixed, "summary": adv["summary"]})
    results.sort(key=lambda r: -RANK[r["severity"]])
    return {"vulnerabilities": results, "unmatched_components": unmatched}


def summary(res) -> dict:
    out = {"total": len(res["vulnerabilities"]), "unmatched": len(res["unmatched_components"])}
    for v in res["vulnerabilities"]:
        out[v["severity"]] = out.get(v["severity"], 0) + 1
    return out


def exit_code(res, fail_on="HIGH") -> int:
    return 1 if any(RANK[v["severity"]] >= RANK[fail_on] for v in res["vulnerabilities"]) else 0
