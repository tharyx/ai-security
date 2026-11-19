"""A tiny IriusRisk-like rules engine (teaching model, not the product).

The flow is the same as a commercial threat modeling platform:
  1. components from a library, placed in trust zones   (the diagram)
  2. answers to questions set component properties     (the questionnaire)
  3. rules add threats and countermeasures              (the rules engine and threat library)
  4. countermeasure states -> inherent vs residual risk (Required / Recommended / Implemented / Not applicable / Rejected)
  5. report and gate on required countermeasures that are not implemented

The multi-cloud part shows one generic threat ("object storage readable by anyone") mapped to three
provider-specific countermeasures (AWS, Azure, Google Cloud). Control names are hedged: verify in each
provider's current documentation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

STATES = {"Required", "Recommended", "Implemented", "Not applicable", "Rejected"}


def load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass
class Countermeasure:
    id: str
    name: str
    weight: float  # share of the risk it removes when implemented (0..1)
    state: str = "Required"


@dataclass
class Threat:
    id: str
    component: str
    title: str
    stride: str
    inherent: int  # 1..25 (likelihood x impact)
    countermeasures: list[Countermeasure] = field(default_factory=list)

    @property
    def residual(self) -> float:
        removed = sum(c.weight for c in self.countermeasures if c.state == "Implemented")
        return round(self.inherent * max(0.0, 1 - removed), 1)


def _matches(cond: dict, props: dict) -> bool:
    return all(props.get(k) == v for k, v in cond.items())


def apply_questionnaire(components: list[dict], answers: dict) -> list[dict]:
    """answers: component name -> {property: value}. Unknown component names are an error."""
    names = {c["name"] for c in components}
    unknown = set(answers) - names
    if unknown:
        raise KeyError(f"answers for unknown components: {sorted(unknown)}")
    return [dict(c, props={**c.get("props", {}), **answers.get(c["name"], {})}) for c in components]


def generate(components: list[dict], library: dict) -> list[Threat]:
    out = []
    for comp in components:
        for rule in library["rules"]:
            if comp["type"] not in rule["component_types"] or not _matches(rule.get("when", {}), comp["props"]):
                continue
            cms = [Countermeasure(cm["id"], cm["by_type"].get(comp["type"], cm.get("name", cm["id"])), cm["weight"])
                   for cm in rule["countermeasures"]]
            out.append(Threat(f"{rule['id']}@{comp['name']}", comp["name"], rule["title"], rule["stride"],
                              rule["inherent"], cms))
    return out


def set_states(threats: list[Threat], states: dict[str, str]) -> None:
    """states: "<CM id>@<component>" -> state."""
    for t in threats:
        for c in t.countermeasures:
            s = states.get(f"{c.id}@{t.component}")
            if s:
                if s not in STATES:
                    raise ValueError(f"unknown state {s!r}")
                c.state = s


def report(threats: list[Threat]) -> dict:
    inherent = sum(t.inherent for t in threats)
    residual = sum(t.residual for t in threats)
    open_required = [f"{c.id}@{t.component} ({c.name})" for t in threats for c in t.countermeasures
                     if c.state == "Required"]
    return {"threats": len(threats), "inherent": inherent, "residual": round(residual, 1),
            "reduction_pct": round(100 * (1 - residual / inherent), 1) if inherent else 0.0,
            "required_not_implemented": open_required}


def gate(threats: list[Threat], max_residual: int = 12) -> int:
    """Fail when any threat's residual risk is above the agreed appetite."""
    return 1 if any(t.residual > max_residual for t in threats) else 0
