"""ThreatSpec-style threat modeling as code, in pure Python.

Reads annotations from source comments (# or //), builds a model, and writes
  * a Markdown threat model report,
  * a Mermaid data flow diagram (DFD),
  * a gate result: exposures with no mitigation and no accepted risk fail the build.

The syntax follows the SHAPE of ThreatSpec (legacy, little development since about 2020)
but is simplified. Verify the real grammar at the ThreatSpec docs before using the real tool.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
          "Elevation of Privilege"]

LINE = re.compile(r"^\s*(?:#|//)\s*@(?P<tag>exposes|mitigates|accepts|connects)\s+(?P<rest>.+?)\s*$")
FORMS = {
    "exposes": re.compile(r"^(?P<comp>\S+)\s+to\s+(?P<threat>.+?)\s+with\s+(?P<text>.+)$"),
    "mitigates": re.compile(r"^(?P<comp>\S+)\s+against\s+(?P<threat>.+?)\s+with\s+(?P<text>.+)$"),
    "accepts": re.compile(r"^(?P<threat>.+?)\s+to\s+(?P<comp>\S+)\s+with\s+(?P<text>.+)$"),
    "connects": re.compile(r"^(?P<src>\S+)\s+to\s+(?P<dst>\S+)\s+with\s+(?P<text>.+)$"),
}


@dataclass
class Item:
    tag: str
    file: str
    line: int
    comp: str = ""
    threat: str = ""
    text: str = ""
    src: str = ""
    dst: str = ""


@dataclass
class Model:
    items: list[Item] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def components(self) -> set[str]:
        out = set()
        for i in self.items:
            out.update(x for x in (i.comp, i.src, i.dst) if x)
        return out

    def exposures(self):
        return [i for i in self.items if i.tag == "exposes"]

    def status(self, comp: str, threat: str) -> str:
        if any(i.tag == "mitigates" and (i.comp, i.threat) == (comp, threat) for i in self.items):
            return "mitigated"
        if any(i.tag == "accepts" and (i.comp, i.threat) == (comp, threat) for i in self.items):
            return "accepted"
        return "UNMITIGATED"

    def unmitigated(self) -> list[Item]:
        return [e for e in self.exposures() if self.status(e.comp, e.threat) == "UNMITIGATED"]

    def orphan_mitigations(self) -> list[Item]:
        exposed = {(e.comp, e.threat) for e in self.exposures()}
        return [i for i in self.items if i.tag == "mitigates" and (i.comp, i.threat) not in exposed]

    def flows(self) -> list[Item]:
        return [i for i in self.items if i.tag == "connects"]


def parse_text(text: str, name: str) -> tuple[list[Item], list[str]]:
    items, errors = [], []
    for n, raw in enumerate(text.splitlines(), 1):
        m = LINE.match(raw)
        if not m:
            if "@" in raw and re.search(r"(?:#|//)\s*@\w+", raw):
                errors.append(f"{name}:{n}: unknown or malformed annotation: {raw.strip()}")
            continue
        tag = m["tag"]
        f = FORMS[tag].match(m["rest"])
        if not f:
            errors.append(f"{name}:{n}: malformed @{tag}: {m['rest']}")
            continue
        d = f.groupdict()
        if tag != "connects" and d["threat"] not in STRIDE:
            errors.append(f"{name}:{n}: threat '{d['threat']}' is not a STRIDE category")
        items.append(Item(tag, name, n, **d))
    return items, errors


def build_model(root: Path) -> Model:
    model = Model()
    for p in sorted(Path(root).rglob("*")):
        if p.suffix in (".py", ".js", ".java", ".go", ".ts") and p.is_file():
            items, errs = parse_text(p.read_text(encoding="utf-8"), p.relative_to(root).as_posix())
            model.items += items
            model.errors += errs
    return model


def gate(model: Model) -> int:
    return 1 if model.unmitigated() or model.errors else 0


def report(model: Model) -> str:
    lines = ["# Threat model report (generated)", "", "| Component | Threat | Status | Evidence |", "|---|---|---|---|"]
    for e in sorted(model.exposures(), key=lambda x: (x.comp, STRIDE.index(x.threat) if x.threat in STRIDE else 9)):
        st = model.status(e.comp, e.threat)
        ev = [f"{i.file}:{i.line}" for i in model.items
              if i.tag in ("mitigates", "accepts") and (i.comp, i.threat) == (e.comp, e.threat)]
        lines.append(f"| {e.comp} | {e.threat} | {st} | {', '.join(ev) or '-'} |")
    lines += ["", "## Unmitigated exposures"]
    um = model.unmitigated()
    lines += [f"- {u.comp}: {u.threat} ({u.text}) at {u.file}:{u.line}" for u in um] or ["- none"]
    if model.orphan_mitigations():
        lines += ["", "## Mitigations with no matching exposure (review)"]
        lines += [f"- {o.comp}: {o.threat} at {o.file}:{o.line}" for o in model.orphan_mitigations()]
    if model.errors:
        lines += ["", "## Annotation errors"] + [f"- {e}" for e in model.errors]
    return "\n".join(lines)


def _id(comp: str) -> str:
    return re.sub(r"\W", "_", comp)


def mermaid(model: Model) -> str:
    zones: dict[str, list[str]] = {}
    for c in sorted(model.components()):
        zone, _, name = c.partition(":")
        zones.setdefault(zone, []).append(c)
    out = ["flowchart LR"]
    bad = {u.comp for u in model.unmitigated()}
    for zone, comps in zones.items():
        out.append(f'  subgraph {_id(zone)}["Trust zone: {zone}"]')
        for c in comps:
            label = c.split(":", 1)[1]
            n_exp = sum(1 for e in model.exposures() if e.comp == c)
            out.append(f'    {_id(c)}["{label}<br/>{n_exp} threats"]')
        out.append("  end")
    for f in model.flows():
        out.append(f'  {_id(f.src)} -->|"{f.text}"| {_id(f.dst)}')
    out.append("  classDef bad fill:#fee2e2,stroke:#dc2626")
    for c in sorted(bad):
        out.append(f"  class {_id(c)} bad")
    return "\n".join(out)
