"""Explore a completed CAIRIS-style model offline.

CAIRIS (Computer Aided Integration of Requirements and Information Security) links usability (personas, tasks),
requirements and security (assets, attackers, threats, vulnerabilities, risks) per ENVIRONMENT.
Real CAIRIS exports are XML with their own DTD and many more fields; this lab uses a SIMPLIFIED,
CAIRIS-inspired XML so you can practise the questions you ask of a completed model. Verify the real format
in the CAIRIS documentation before parsing real exports.

Safety: XML can carry XXE and entity-expansion attacks. The loader refuses any DOCTYPE or ENTITY.
For untrusted XML in real code use defusedxml.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

LIKELIHOOD = {"Incredible": 0, "Improbable": 1, "Remote": 2, "Occasional": 3, "Probable": 4, "Frequent": 5}
SEVERITY = {"Negligible": 1, "Marginal": 2, "Critical": 3, "Catastrophic": 4}


def safe_parse(text: str) -> ET.Element:
    head = text[:2000].upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise ValueError("DOCTYPE/ENTITY not allowed (XXE and billion-laughs protection)")
    return ET.fromstring(text)


def load(path: Path) -> ET.Element:
    return safe_parse(Path(path).read_text(encoding="utf-8"))


@dataclass
class Risk:
    name: str
    environment: str
    threat: str
    vulnerability: str
    asset: str
    attackers: list[str]
    score: int  # likelihood x severity, 0..20


def risks(root: ET.Element) -> list[Risk]:
    threats = {t.get("name"): t for t in root.iter("threat")}
    vulns = {v.get("name"): v for v in root.iter("vulnerability")}
    out = []
    for r in root.iter("risk"):
        t, v = threats[r.get("threat")], vulns[r.get("vulnerability")]
        env = r.get("environment")
        asset = t.find("target").get("asset")
        attackers = [a.get("name") for a in t.findall("attacker")]
        score = LIKELIHOOD[t.get("likelihood")] * SEVERITY[v.get("severity")]
        out.append(Risk(r.get("name"), env, t.get("name"), v.get("name"), asset, attackers, score))
    return sorted(out, key=lambda x: -x.score)


def environments(root: ET.Element) -> list[str]:
    return [e.get("name") for e in root.iter("environment")]


def unprotected_assets(root: ET.Element) -> list[str]:
    """Assets that some risk targets but that no requirement or countermeasure mentions."""
    protected = {c.get("asset") for c in root.iter("countermeasure")} | {q.get("asset") for q in root.iter("requirement")}
    at_risk = {r.asset for r in risks(root)}
    return sorted(at_risk - protected)


def attacker_paths(root: ET.Element) -> list[str]:
    return [f"{a} -> {r.threat} -> {r.asset} ({r.environment}, score {r.score})" for r in risks(root) for a in r.attackers]


def persona_tasks_at_risk(root: ET.Element) -> list[str]:
    """Usability view: which persona tasks touch an asset with a risk score of 12 or more."""
    hot = {r.asset for r in risks(root) if r.score >= 12}
    out = []
    for task in root.iter("task"):
        touched = [u.get("asset") for u in task.findall("uses") if u.get("asset") in hot]
        if touched:
            out.append(f"{task.get('persona')}: '{task.get('name')}' uses high-risk {touched}")
    return out
