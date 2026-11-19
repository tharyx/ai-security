"""A small threat-modeling tool: YAML DFD -> STRIDE per element -> risk register + Mermaid.

Pipeline (the same steps as the chapter lessons):

    1. load_dfd()        read the YAML and check the field names (pydantic)
    2. validate_dfd()    check DFD rules (known zones, flows end at real elements, ...)
    3. stride_threats()  apply STRIDE per element and enrich from a local threat library
    4. rate()            OWASP-style risk rating: likelihood x impact -> severity
    5. build_register()  list every threat with inherent and residual severity
    6. to_mermaid()      draw the DFD as a Mermaid flowchart

Self-contained on purpose. It reuses the ideas of 01-ai-security-fundamentals/lab/threat_model.py
(STRIDE per element, controls) but does not import it.

Usage (from the repository root):
    python caisp-course/ch5-threat-modeling-ai-systems/labs/threat-model-ai-system/tm_tool.py DFD.yaml
    ... tm_tool.py DFD.yaml --format json|csv --mermaid

Exit code 1 when an OPEN threat has High or Critical severity (so CI can block a merge).
"""

from __future__ import annotations

import csv
import io
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

HERE = Path(__file__).resolve().parent
DEFAULT_LIBRARY = HERE / "threat_library.yaml"

STRIDE_NAMES = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}

# Classic STRIDE-per-element (Microsoft). External entity: S, R. Process: all six.
# Data store: T, R, I, D. Data flow: T, I, D.
STRIDE_PER_ELEMENT: dict[str, str] = {
    "external_entity": "SR",
    "process": "STRIDE",
    "data_store": "TRID",
    "data_flow": "TID",
}

# A control is any short name. The library says which controls mitigate which threat.
VULN_REDUCTION_PER_CONTROL = 3.0

# ------------------------------------------------------------------------------------
# Schema
# ------------------------------------------------------------------------------------

ElementKind = Literal["external_entity", "process", "data_store"]


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    value: float = Field(ge=0, le=9)


class Zone(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    trust: Literal["untrusted", "semi", "trusted", "third_party"]
    name: str = ""


class Element(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: ElementKind
    zone: str
    name: str = ""
    tags: list[str] = []
    assets: list[str] = []
    controls: list[str] = []


class Flow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    source: str
    target: str
    data: str = ""
    tags: list[str] = []
    controls: list[str] = []


class DFD(BaseModel):
    model_config = ConfigDict(extra="forbid")
    system: str
    description: str = ""
    assets: list[Asset] = []
    zones: list[Zone]
    elements: list[Element]
    flows: list[Flow]


class FactorSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: float = Field(ge=0, le=9)
    vuln: float = Field(ge=0, le=9)
    tech: float = Field(ge=0, le=9)
    business: float = Field(ge=0, le=9)


class LibraryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    stride: Literal["S", "T", "R", "I", "D", "E"]
    applies_to: list[Literal["external_entity", "process", "data_store", "data_flow"]]
    when_tags: list[str] = []
    owasp_llm: list[str] = []
    atlas: list[str] = []
    biml: dict[str, str] = {}
    factors: FactorSet
    mitigated_by: list[str] = []
    mitigation: str = ""


class ThreatLibrary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[LibraryEntry]


def load_dfd(path: str | Path) -> DFD:
    return DFD.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def load_library(path: str | Path = DEFAULT_LIBRARY) -> ThreatLibrary:
    return ThreatLibrary.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


# ------------------------------------------------------------------------------------
# Step 2: DFD validation
# ------------------------------------------------------------------------------------


@dataclass
class Issue:
    level: str  # error | warning
    message: str


def validate_dfd(dfd: DFD) -> list[Issue]:
    """Check the DFD rules. Errors mean the diagram is not a valid DFD."""
    issues: list[Issue] = []
    zone_ids = {z.id for z in dfd.zones}
    asset_ids = {a.id for a in dfd.assets}
    kinds: dict[str, str] = {}

    ids = [e.id for e in dfd.elements] + [f.id for f in dfd.flows]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        issues.append(Issue("error", f"duplicate id: {dup}"))

    for e in dfd.elements:
        kinds[e.id] = e.type
        if e.zone not in zone_ids:
            issues.append(Issue("error", f"element {e.id}: unknown zone '{e.zone}'"))
        for a in e.assets:
            if a not in asset_ids:
                issues.append(Issue("error", f"element {e.id}: unknown asset '{a}'"))

    touched: set[str] = set()
    for f in dfd.flows:
        for end, label in ((f.source, "source"), (f.target, "target")):
            if end not in kinds:
                issues.append(Issue("error", f"flow {f.id}: unknown {label} '{end}'"))
        if f.source in kinds and f.target in kinds:
            touched.update({f.source, f.target})
            if "process" not in (kinds[f.source], kinds[f.target]):
                issues.append(Issue(
                    "error",
                    f"flow {f.id}: {kinds[f.source]} -> {kinds[f.target]} has no process end. "
                    "Data never moves by itself; a process must read or write it.",
                ))
    for e in dfd.elements:
        if e.id not in touched:
            issues.append(Issue("warning", f"element {e.id} has no data flow (orphan)"))
    for e in dfd.elements:
        if e.type == "data_store" and not any(f.target == e.id for f in dfd.flows):
            issues.append(Issue("warning", f"data store {e.id} is never written"))
    return issues


# ------------------------------------------------------------------------------------
# Step 4: OWASP-style risk rating
# ------------------------------------------------------------------------------------


def level(score: float) -> str:
    """OWASP Risk Rating levels: 0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH."""
    if score < 3:
        return "LOW"
    if score < 6:
        return "MEDIUM"
    return "HIGH"


# Overall severity = f(likelihood level, impact level), as in the OWASP methodology.
SEVERITY_MATRIX = {
    ("LOW", "LOW"): "NOTE", ("MEDIUM", "LOW"): "LOW", ("HIGH", "LOW"): "MEDIUM",
    ("LOW", "MEDIUM"): "LOW", ("MEDIUM", "MEDIUM"): "MEDIUM", ("HIGH", "MEDIUM"): "HIGH",
    ("LOW", "HIGH"): "MEDIUM", ("MEDIUM", "HIGH"): "HIGH", ("HIGH", "HIGH"): "CRITICAL",
}  # keys are (likelihood, impact)

SEVERITY_ORDER = ["NOTE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def mean(values: list[float] | float) -> float:
    if isinstance(values, (int, float)):
        return float(values)
    return sum(values) / len(values)


def rate(agent, vuln, tech, business) -> dict[str, float | str]:
    """OWASP-style rating.

    Each argument is a score 0-9, or a list of factor scores (the OWASP method has
    four factors per group: skill level, motive, opportunity, size; ease of discovery,
    ease of exploit, awareness, intrusion detection; and so on).
    likelihood = mean(agent, vuln); impact = mean(tech, business).
    """
    likelihood = (mean(agent) + mean(vuln)) / 2
    impact = (mean(tech) + mean(business)) / 2
    lk, im = level(likelihood), level(impact)
    return {
        "likelihood": round(likelihood, 2), "impact": round(impact, 2),
        "likelihood_level": lk, "impact_level": im,
        "severity": SEVERITY_MATRIX[(lk, im)],
    }


def treatment(severity: str, controlled: bool) -> str:
    """A first suggestion. A person decides (avoid / mitigate / transfer / accept)."""
    if severity == "CRITICAL":
        return "mitigate now (or avoid the feature)"
    if severity == "HIGH":
        return "mitigate before release"
    if severity == "MEDIUM":
        return "mitigate or transfer; plan it" if not controlled else "accept with monitoring"
    return "accept and monitor"


# ------------------------------------------------------------------------------------
# Step 3 and 5: STRIDE per element, enrichment, register
# ------------------------------------------------------------------------------------


@dataclass
class Subject:
    """Something STRIDE is applied to: a DFD element or a data flow."""
    id: str
    kind: str  # external_entity | process | data_store | data_flow
    name: str
    tags: set[str]
    controls: set[str]
    asset_values: list[float] = field(default_factory=list)


def subjects(dfd: DFD) -> list[Subject]:
    asset_value = {a.id: a.value for a in dfd.assets}
    out: list[Subject] = []
    by_id = {e.id: e for e in dfd.elements}
    for e in dfd.elements:
        out.append(Subject(e.id, e.type, e.name or e.id, set(e.tags), set(e.controls),
                           [asset_value[a] for a in e.assets if a in asset_value]))
    for f in dfd.flows:
        src, dst = by_id.get(f.source), by_id.get(f.target)
        label = f"{f.id}: {src.name if src else f.source} -> {dst.name if dst else f.target} ({f.data})"
        vals = []
        for end in (src, dst):
            if end:
                vals += [asset_value[a] for a in end.assets if a in asset_value]
        out.append(Subject(f.id, "data_flow", label, set(f.tags), set(f.controls), vals))
    return out


@dataclass
class Threat:
    id: str
    subject: str
    subject_kind: str
    stride: str
    title: str
    library_id: str
    owasp_llm: list[str]
    atlas: list[str]
    biml: dict[str, str]
    likelihood: float
    impact: float
    severity: str
    residual_severity: str
    controls_present: list[str]
    controls_missing: list[str]
    status: str  # open | controlled
    treatment: str
    mitigation: str


GENERIC_FACTORS = FactorSet(agent=4, vuln=5, tech=4, business=4)


def _matches(entry: LibraryEntry, subject: Subject, letter: str) -> bool:
    if entry.stride != letter or subject.kind not in entry.applies_to:
        return False
    return not entry.when_tags or bool(set(entry.when_tags) & subject.tags)


def stride_threats(dfd: DFD, library: ThreatLibrary) -> list[Threat]:
    """Apply STRIDE per element and enrich every threat from the library."""
    threats: list[Threat] = []
    counter = 0
    for subj in subjects(dfd):
        for letter in STRIDE_PER_ELEMENT[subj.kind]:
            entries = [e for e in library.entries if _matches(e, subj, letter)]
            if not entries:
                # Nothing in the library fits: keep a generic candidate so a human reviews it.
                entries = [LibraryEntry(
                    id="GENERIC", title=f"{STRIDE_NAMES[letter]} threat to review",
                    stride=letter, applies_to=[subj.kind], factors=GENERIC_FACTORS,
                    mitigation="No library entry matched. Review by hand and add one.",
                )]
            for entry in entries:
                counter += 1
                threats.append(_make_threat(f"T{counter:03d}", subj, entry))
    return threats


def _make_threat(tid: str, subj: Subject, entry: LibraryEntry) -> Threat:
    f = entry.factors
    business = f.business
    if subj.asset_values:  # asset value pulls the business impact toward what is at stake
        business = (f.business + max(subj.asset_values)) / 2
    inherent = rate(f.agent, f.vuln, f.tech, business)
    present = sorted(subj.controls & set(entry.mitigated_by))
    missing = sorted(set(entry.mitigated_by) - subj.controls)
    vuln = max(0.0, f.vuln - VULN_REDUCTION_PER_CONTROL * len(present))
    residual = rate(f.agent, vuln, f.tech, business)
    controlled = bool(present)
    shown = residual if controlled else inherent
    return Threat(
        id=tid, subject=subj.name if subj.kind == "data_flow" else f"{subj.id} ({subj.name})",
        subject_kind=subj.kind, stride=entry.stride, title=entry.title, library_id=entry.id,
        owasp_llm=entry.owasp_llm, atlas=entry.atlas, biml=entry.biml,
        likelihood=float(shown["likelihood"]), impact=float(shown["impact"]),
        severity=str(inherent["severity"]), residual_severity=str(residual["severity"]),
        controls_present=present, controls_missing=missing,
        status="controlled" if controlled else "open",
        treatment=treatment(str(residual["severity"]), controlled), mitigation=entry.mitigation,
    )


def build_register(dfd: DFD, library: ThreatLibrary) -> list[Threat]:
    """The risk register: every threat, highest residual severity first."""
    threats = stride_threats(dfd, library)
    return sorted(
        threats,
        key=lambda t: (-SEVERITY_ORDER.index(t.residual_severity), -t.likelihood * t.impact, t.id),
    )


def blocking(register: list[Threat]) -> list[Threat]:
    """Open threats that are High or Critical after existing controls."""
    return [t for t in register if t.status == "open" and t.residual_severity in ("HIGH", "CRITICAL")]


# ------------------------------------------------------------------------------------
# Step 6: Mermaid DFD
# ------------------------------------------------------------------------------------


def to_mermaid(dfd: DFD) -> str:
    """A Mermaid flowchart: one subgraph per trust zone = the trust boundaries."""
    shape = {"external_entity": ("[", "]"), "process": ("((", "))"), "data_store": ("[(", ")]")}
    lines = ["flowchart LR"]
    for z in dfd.zones:
        members = [e for e in dfd.elements if e.zone == z.id]
        if not members:
            continue
        lines.append(f'  subgraph {z.id}["{z.name or z.id} ({z.trust})"]')
        for e in members:
            o, c = shape[e.type]
            lines.append(f'    {e.id}{o}"{e.name or e.id}"{c}')
        lines.append("  end")
    for f in dfd.flows:
        label = f"{f.id}: {f.data}".replace('"', "'")
        lines.append(f'  {f.source} -->|"{label}"| {f.target}')
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------------


def to_json(register: list[Threat]) -> str:
    return json.dumps([asdict(t) for t in register], indent=2)


def to_csv(register: list[Threat]) -> str:
    buf = io.StringIO()
    cols = ["id", "subject", "stride", "title", "library_id", "owasp_llm", "atlas", "likelihood",
            "impact", "severity", "residual_severity", "status", "treatment", "mitigation"]
    w = csv.writer(buf)
    w.writerow(cols)
    for t in register:
        row = asdict(t)
        w.writerow([";".join(row[c]) if isinstance(row[c], list) else row[c] for c in cols])
    return buf.getvalue()


def to_table(register: list[Threat], top: int | None = None) -> str:
    rows = register[:top] if top else register
    out = [f"{'ID':5} {'STRIDE':6} {'SEVERITY':9} {'STATUS':10} {'OWASP LLM (2023)':24} THREAT / WHERE"]
    for t in rows:
        owasp = ", ".join(x.split(" ")[0] for x in t.owasp_llm) or "-"
        out.append(f"{t.id:5} {t.stride:6} {t.residual_severity:9} {t.status:10} {owasp:24} "
                   f"{t.title} @ {t.subject}")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    dfd = load_dfd(argv[0])
    fmt = argv[argv.index("--format") + 1] if "--format" in argv else "table"
    issues = validate_dfd(dfd)
    for i in issues:
        print(f"[{i.level}] {i.message}", file=sys.stderr)
    if any(i.level == "error" for i in issues):
        return 2
    register = build_register(dfd, load_library())
    if "--mermaid" in argv:
        print(to_mermaid(dfd))
        return 0
    print({"json": to_json, "csv": to_csv}.get(fmt, to_table)(register))
    return 1 if blocking(register) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
