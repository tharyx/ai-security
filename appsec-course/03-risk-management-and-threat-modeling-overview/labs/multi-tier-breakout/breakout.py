"""Breakout-session checker: threats for a multi-tiered application.

Teams list threats as (element, STRIDE letter, text, mitigation). The checker:

* computes the trust-boundary crossings and the external attack surface of the system,
* compares a team's list with the facilitator's answer key,
* flags unknown elements, invalid STRIDE letters, missing mitigations, and
  letters that are unusual for the element type (STRIDE per element),
* passes a team only if every "must" threat is found, coverage is at least 60 %, and
  every submitted threat has a mitigation and a valid element and letter.

Standard library only. All data is fictional.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
          "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
# Classic STRIDE-per-element table (Microsoft SDL). Data stores get R only when they hold logs.
TYPICAL = {"external": set("SR"), "process": set("STRIDE"), "datastore": set("TID"), "flow": set("TID")}
PASS_COVERAGE = 0.6


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def element_type(system: dict, eid: str) -> str | None:
    for e in system["elements"]:
        if e["id"] == eid:
            return e["type"]
    if any(f["id"] == eid for f in system["flows"]):
        return "flow"
    return None


def typical_letters(system: dict, eid: str) -> set[str]:
    etype = element_type(system, eid)
    letters = set(TYPICAL.get(etype, set()))
    if etype == "datastore":
        el = next(e for e in system["elements"] if e["id"] == eid)
        if el.get("holds_logs"):
            letters.add("R")
    return letters


def validate_system(system: dict) -> list[str]:
    ids = {e["id"] for e in system["elements"]}
    errors = []
    for f in system["flows"]:
        for end in ("src", "dst"):
            if f[end] not in ids:
                errors.append(f"{f['id']}: unknown {end} '{f[end]}'")
    for e in system["elements"]:
        if e["zone"] not in system["zones"]:
            errors.append(f"{e['id']}: unknown zone '{e['zone']}'")
    return errors


def _zone(system: dict, eid: str) -> str:
    return next(e["zone"] for e in system["elements"] if e["id"] == eid)


def boundary_crossings(system: dict) -> list[dict]:
    """Flows whose two ends sit in different trust zones (either direction)."""
    out = []
    for f in system["flows"]:
        zs, zd = _zone(system, f["src"]), _zone(system, f["dst"])
        if zs != zd:
            out.append({"flow": f["id"], "from": zs, "to": zd,
                        "inbound": system["zones"][zs] < system["zones"][zd]})
    return out


def attack_surface(system: dict) -> list[str]:
    """Entry points an outside actor can reach directly: flows that start at an external entity."""
    types = {e["id"]: e["type"] for e in system["elements"]}
    return [f"{f['dst']} via {f['id']} ({f['label']})" for f in system["flows"] if types[f["src"]] == "external"]


@dataclass
class Result:
    team: str
    matched: list[str] = field(default_factory=list)
    missing_must: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage: float = 0.0

    @property
    def passed(self) -> bool:
        return not self.missing_must and self.coverage >= PASS_COVERAGE and not self.errors


def check(submission: dict, key: dict, system: dict) -> Result:
    res = Result(team=submission.get("team", "?"))
    found = set()
    for i, t in enumerate(submission["threats"], 1):
        tag = f"#{i} {t.get('element')}/{t.get('stride')}"
        etype = element_type(system, t.get("element", ""))
        if etype is None:
            res.errors.append(f"{tag}: UNKNOWN_ELEMENT")
            continue
        if t.get("stride") not in STRIDE:
            res.errors.append(f"{tag}: INVALID_STRIDE_LETTER")
            continue
        if not t.get("mitigation", "").strip():
            res.errors.append(f"{tag}: NO_MITIGATION")
        if t["stride"] not in typical_letters(system, t["element"]):
            res.warnings.append(f"{tag}: unusual letter for a {etype} (allowed, but justify it)")
        found.add((t["element"], t["stride"]))
    key_pairs = {(k["element"], k["stride"]) for k in key["threats"]}
    for k in key["threats"]:
        pair = (k["element"], k["stride"])
        if pair in found:
            res.matched.append(k["id"])
        elif k["must"]:
            res.missing_must.append(f"{k['id']} {k['element']}/{k['stride']}: {k['text']}")
        else:
            res.missing_optional.append(f"{k['id']} {k['element']}/{k['stride']}: {k['text']}")
    res.extra = sorted(f"{e}/{s}" for e, s in found - key_pairs)
    res.coverage = round(len(res.matched) / len(key["threats"]), 2)
    return res


def render(res: Result) -> str:
    lines = [f"--- {res.team}: coverage {res.coverage:.0%}, {'PASS' if res.passed else 'FAIL'} ---"]
    for title, items in (("Missing MUST threats", res.missing_must), ("Errors", res.errors),
                         ("Warnings", res.warnings), ("Not in the key (review, may be valid)", res.extra),
                         ("Missing optional threats", res.missing_optional)):
        if items:
            lines.append(f"{title}:")
            lines.extend(f"  - {x}" for x in items)
    return "\n".join(lines)
