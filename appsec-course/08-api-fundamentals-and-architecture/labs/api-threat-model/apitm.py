"""A small API threat-model engine: STRIDE per element + API defense coverage.

The CASP 1 syllabus lists "Threat Modeling of APIs" and eight "API Defenses"
(Input Validation, Identification, Authentication, Authorization, Data
Encryption, Transport Security, Error Handling and Logging, Supply Chain
Security). This lab turns a JSON-ish description of an API deployment into:

* a STRIDE-per-element threat list (processes face all six, data stores face
  Tampering / Information disclosure / DoS / Repudiation, flows face
  Tampering / Information disclosure / DoS), and
* a **defense coverage gate**: every element that handles requests must declare
  the defenses relevant to it, or the gate fails and names the gap.

Two fixtures are built in code: a "simple" deployment that skips defenses
(vulnerable) and a "hardened" one that declares them (secure). The tests assert
that the gate flags the simple one and passes the hardened one.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

from dataclasses import dataclass, field

STRIDE = [
    "Spoofing", "Tampering", "Repudiation",
    "Information disclosure", "Denial of service", "Elevation of privilege",
]

# Which STRIDE letters apply to each element kind (classic STRIDE-per-element).
APPLIES = {
    "external": ["Spoofing", "Repudiation"],
    "process": STRIDE,
    "datastore": ["Tampering", "Repudiation", "Information disclosure", "Denial of service"],
    "flow": ["Tampering", "Information disclosure", "Denial of service"],
}

# The eight API defense categories from the syllabus.
DEFENSES = [
    "input_validation", "identification", "authentication", "authorization",
    "data_encryption", "transport_security", "error_handling_logging",
    "supply_chain_security",
]

# Which defenses a given element kind is expected to declare.
REQUIRED_DEFENSES = {
    "process": ["input_validation", "identification", "authentication",
                "authorization", "error_handling_logging", "supply_chain_security"],
    "datastore": ["data_encryption", "authorization"],
    "flow": ["transport_security"],
    "external": [],
}


@dataclass
class Element:
    name: str
    kind: str  # external | process | datastore | flow
    zone: str  # trust zone label
    defenses: set = field(default_factory=set)


@dataclass
class Threat:
    element: str
    kind: str
    category: str  # STRIDE letter


@dataclass
class Gap:
    element: str
    defense: str


def enumerate_threats(elements: list) -> list:
    """STRIDE-per-element: one Threat per (element, applicable category)."""
    threats = []
    for el in elements:
        for cat in APPLIES.get(el.kind, []):
            threats.append(Threat(element=el.name, kind=el.kind, category=cat))
    return threats


def defense_gaps(elements: list) -> list:
    """Return the required-but-missing defenses across all elements."""
    gaps = []
    for el in elements:
        for needed in REQUIRED_DEFENSES.get(el.kind, []):
            if needed not in el.defenses:
                gaps.append(Gap(element=el.name, defense=needed))
    return gaps


def gate(elements: list) -> int:
    """Exit 1 if any required defense is missing, else 0."""
    return 1 if defense_gaps(elements) else 0


def crosses_boundary(flow: Element, by_name: dict) -> bool:
    """True if a flow connects two elements in different trust zones."""
    src = by_name.get(getattr(flow, "src", ""))
    dst = by_name.get(getattr(flow, "dst", ""))
    return bool(src and dst and src.zone != dst.zone)


def report(elements: list) -> str:
    threats = enumerate_threats(elements)
    gaps = defense_gaps(elements)
    lines = ["# API threat model (generated)", "",
             f"Elements: {len(elements)}  Threats: {len(threats)}  Defense gaps: {len(gaps)}", ""]
    lines.append("## STRIDE per element")
    for t in threats:
        lines.append(f"- {t.element} ({t.kind}): {t.category}")
    lines.append("")
    lines.append("## Missing API defenses")
    if gaps:
        for g in gaps:
            lines.append(f"- {g.element}: missing {g.defense}")
    else:
        lines.append("- none; all required defenses declared")
    lines.append("")
    lines.append(f"gate exit code: {gate(elements)}")
    return "\n".join(lines)


# --- fixtures --------------------------------------------------------------
def simple_deployment() -> list:
    """A naive 'simple architecture': client -> one API process -> DB.

    It declares almost no defenses, so the gate must fail.
    """
    return [
        Element("MobileApp", "external", "Internet"),
        Element("OrdersAPI", "process", "AppTier", defenses={"authentication"}),
        Element("OrdersDB", "datastore", "DataTier", defenses=set()),
        _flow("ClientToApi", "Internet", "MobileApp", "OrdersAPI", defenses=set()),
    ]


def hardened_deployment() -> list:
    """A 'complex architecture' that declares every required defense."""
    return [
        Element("MobileApp", "external", "Internet"),
        Element("Gateway", "process", "Edge", defenses=set(
            ["input_validation", "identification", "authentication",
             "authorization", "error_handling_logging", "supply_chain_security"])),
        Element("OrdersAPI", "process", "AppTier", defenses=set(
            ["input_validation", "identification", "authentication",
             "authorization", "error_handling_logging", "supply_chain_security"])),
        Element("OrdersDB", "datastore", "DataTier",
                defenses={"data_encryption", "authorization"}),
        _flow("EdgeToApp", "Edge", "Gateway", "OrdersAPI",
              defenses={"transport_security"}),
        _flow("AppToDb", "DataTier", "OrdersAPI", "OrdersDB",
              defenses={"transport_security"}),
    ]


def _flow(name, zone, src, dst, defenses):
    el = Element(name, "flow", zone, defenses=defenses)
    el.src = src
    el.dst = dst
    return el
