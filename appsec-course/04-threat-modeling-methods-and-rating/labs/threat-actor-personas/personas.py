"""Threat actor personas mapped to MITRE ATT&CK technique IDs (attacker-centric modeling).

A persona is a short, evidence-based profile of WHO attacks you: motivation, skill,
resources, access, goals and the techniques they typically use. Threats in the model are
tagged with ATT&CK technique IDs. The tool answers:

* Is each persona well formed? (required fields, known technique IDs)
* Which ATT&CK tactics does a persona cover?
* Which threats is each persona likely to attempt? (technique overlap + enough skill + access)
* Which threats have no ATT&CK mapping (often business-logic abuse ATT&CK does not model)?
* Which mapped threats no persona would attempt (a missing persona, or an unrealistic threat)?

The technique subset in fixtures/attack_techniques.json is small and hand-copied for
teaching. Verify IDs and names at attack.mitre.org; ATT&CK is versioned and changes.
"""
from __future__ import annotations

import json
from pathlib import Path

REQUIRED = ("name", "motivation", "skill", "resources", "access", "goals", "techniques")


def load(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_persona(p: dict, techniques: dict) -> list[str]:
    errs = [f"MISSING_{f.upper()}" for f in REQUIRED if not p.get(f)]
    if p.get("skill") is not None and not (1 <= p["skill"] <= 5):
        errs.append("SKILL_OUT_OF_RANGE")
    errs += [f"UNKNOWN_TECHNIQUE {t}" for t in p.get("techniques", []) if t not in techniques]
    return errs


def tactics_for(p: dict, techniques: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for t in p["techniques"]:
        for tactic in techniques[t]["tactics"]:
            out.setdefault(tactic, []).append(t)
    return out


def would_attempt(p: dict, threat: dict) -> bool:
    overlap = set(p["techniques"]) & set(threat["attack"])
    return bool(overlap) and p["skill"] >= threat["min_skill"] and threat["access"] in p["access"]


def relevant_threats(p: dict, threats: list[dict]) -> list[str]:
    return [t["id"] for t in threats if would_attempt(p, t)]


def unmapped_threats(threats: list[dict]) -> list[str]:
    return [t["id"] for t in threats if not t["attack"]]


def uncovered_threats(personas: list[dict], threats: list[dict]) -> list[str]:
    return [t["id"] for t in threats if t["attack"] and not any(would_attempt(p, t) for p in personas)]


def card(p: dict, techniques: dict) -> str:
    """A one-screen persona card for the threat model document."""
    lines = [f"### {p['name']}",
             f"- Motivation: {p['motivation']}",
             f"- Skill: {p['skill']}/5; resources: {p['resources']}; access: {', '.join(p['access'])}",
             f"- Goals: {'; '.join(p['goals'])}",
             "- Techniques (ATT&CK, verify IDs):"]
    for t in p["techniques"]:
        lines.append(f"  - {t} {techniques[t]['name']} ({', '.join(techniques[t]['tactics'])})")
    return "\n".join(lines)
