"""STRIDE per element and per crossing for an MCP architecture described in YAML.

Pipeline:
    load_arch()      read the YAML architecture (host, servers, OAuth server, registry, stores, flows)
    validate()       DFD rules: unique ids, known zones, flows end at real elements, no store-to-store flows
    crossings()      which data flows cross a trust boundary (different zones)
    find_threats()   apply the MCP threat library (STRIDE letter per element kind) and mark each finding
                     "open" or "mitigated" depending on the controls the architecture already lists
    to_mermaid()     draw the DFD as a Mermaid flowchart (subgraphs are trust boundaries)

Usage (from the repository root):
    python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/stride_mcp.py
    ... stride_mcp.py ARCH.yaml --format md|json|csv --mermaid

The library is an educational starting point, not a complete catalogue. A human must review every finding.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_ARCH = HERE / "mcp_architecture.yaml"
DEFAULT_LIBRARY = HERE / "mcp_threat_library.yaml"

STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}

# Classic STRIDE-per-element: which letters make sense for which DFD element type.
STRIDE_PER_ELEMENT = {"external_entity": "SR", "process": "STRIDE", "data_store": "TRID", "data_flow": "TID"}


def load_arch(path: str | Path = DEFAULT_ARCH) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_library(path: str | Path = DEFAULT_LIBRARY) -> list[dict]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["entries"]


# ----------------------------------------------------------------------------- validation

def validate(arch: dict) -> list[str]:
    """Return a list of problems (empty list = the DFD obeys the basic rules)."""
    problems: list[str] = []
    zones = {z["id"] for z in arch.get("zones", [])}
    elements = {}
    for e in arch.get("elements", []):
        if e["id"] in elements:
            problems.append(f"duplicate element id {e['id']}")
        elements[e["id"]] = e
        if e["zone"] not in zones:
            problems.append(f"element {e['id']} uses unknown zone {e['zone']}")
        if e["type"] not in ("external_entity", "process", "data_store"):
            problems.append(f"element {e['id']} has unknown type {e['type']}")
    seen = set()
    for f in arch.get("flows", []):
        if f["id"] in seen:
            problems.append(f"duplicate flow id {f['id']}")
        seen.add(f["id"])
        for end in ("source", "target"):
            if f[end] not in elements:
                problems.append(f"flow {f['id']} {end} {f[end]} is not an element")
        if f["source"] in elements and f["target"] in elements:
            a, b = elements[f["source"]]["type"], elements[f["target"]]["type"]
            if a != "process" and b != "process":
                problems.append(f"flow {f['id']} connects {a} to {b}; one end of every flow must be a process")
    return problems


def _zone_map(arch: dict) -> dict[str, dict]:
    return {z["id"]: z for z in arch["zones"]}


def crossings(arch: dict) -> set[str]:
    """Ids of data flows whose two ends are in different zones (they cross a trust boundary)."""
    el = {e["id"]: e for e in arch["elements"]}
    return {f["id"] for f in arch["flows"] if el[f["source"]]["zone"] != el[f["target"]]["zone"]}


# ----------------------------------------------------------------------------- threats

@dataclass
class Finding:
    id: str
    element_id: str
    element_name: str
    kind: str                 # external_entity | process | data_store | data_flow
    library_id: str
    stride: str
    title: str
    crossing: bool            # for data flows: crosses a trust boundary
    owasp_mcp: list[str]
    asi: list[str]
    status: str               # open | mitigated
    present_controls: list[str]
    missing_controls: list[str]
    mitigation: str
    assets: list[str] = field(default_factory=list)
    factors: dict = field(default_factory=dict)

    def as_row(self) -> dict:
        d = asdict(self)
        for k in ("owasp_mcp", "asi", "present_controls", "missing_controls", "assets"):
            d[k] = ";".join(d[k])
        d.pop("factors")
        return d


def _subjects(arch: dict):
    """Yield (id, name, kind, tags, controls, assets, crossing) for every element and every flow."""
    cross = crossings(arch)
    for e in arch["elements"]:
        yield e["id"], e.get("name", e["id"]), e["type"], set(e.get("tags", [])), set(e.get("controls", [])), \
            e.get("assets", []), False
    el = {e["id"]: e for e in arch["elements"]}
    for f in arch["flows"]:
        src, dst = el[f["source"]], el[f["target"]]
        name = f"{f['id']} {src.get('name', src['id'])} -> {dst.get('name', dst['id'])}"
        # A flow also inherits the assets of both ends: data in motion is the same data.
        assets = sorted(set(src.get("assets", [])) | set(dst.get("assets", [])))
        yield f["id"], name, "data_flow", set(f.get("tags", [])), set(f.get("controls", [])), assets, f["id"] in cross


def find_threats(arch: dict, library: list[dict] | None = None) -> list[Finding]:
    """Apply STRIDE per element and per boundary crossing using the MCP threat library."""
    library = library if library is not None else load_library()
    findings: list[Finding] = []
    n = 0
    for sid, name, kind, tags, controls, assets, crossing in _subjects(arch):
        for entry in library:
            if entry["stride"] not in STRIDE_PER_ELEMENT[kind]:
                continue
            if kind not in entry["applies_to"]:
                continue
            if entry.get("when_tags") and not (tags & set(entry["when_tags"])):
                continue
            if entry.get("boundary_only") and not crossing:
                continue
            wanted = list(entry.get("mitigated_by", []))
            present = [c for c in wanted if c in controls]
            n += 1
            findings.append(Finding(
                id=f"FND-{n:03d}", element_id=sid, element_name=name, kind=kind, library_id=entry["id"],
                stride=entry["stride"], title=entry["title"], crossing=crossing,
                owasp_mcp=list(entry.get("owasp_mcp", [])), asi=list(entry.get("asi", [])),
                status="mitigated" if present else "open",
                present_controls=present, missing_controls=[c for c in wanted if c not in present],
                mitigation=entry.get("mitigation", ""), assets=list(assets),
                factors=dict(entry["factors"])))
    return findings


def summary(findings: list[Finding]) -> dict:
    by_stride = {k: 0 for k in STRIDE_NAMES}
    for f in findings:
        by_stride[f.stride] += 1
    return {"total": len(findings), "open": sum(f.status == "open" for f in findings),
            "mitigated": sum(f.status == "mitigated" for f in findings),
            "crossing_flows": sum(1 for f in findings if f.crossing), "by_stride": by_stride}


# ----------------------------------------------------------------------------- output

def to_markdown(findings: list[Finding], arch: dict) -> str:
    s = summary(findings)
    lines = [f"# STRIDE findings: {arch['system']}", "",
             f"{s['total']} findings, {s['open']} open, {s['mitigated']} mitigated by existing controls.", "",
             "| ID | Element | STRIDE | Threat | OWASP MCP | Status | Missing controls |", "|---|---|---|---|---|---|---|"]
    for f in findings:
        mark = " (crosses boundary)" if f.crossing else ""
        lines.append(f"| {f.id} | {f.element_name}{mark} | {f.stride} | {f.title} | {', '.join(f.owasp_mcp) or '-'} "
                     f"| {f.status} | {', '.join(f.missing_controls) or '-'} |")
    return "\n".join(lines) + "\n"


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    rows = [f.as_row() for f in findings]
    w = csv.DictWriter(buf, fieldnames=list(rows[0]) if rows else ["id"])
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def to_mermaid(arch: dict) -> str:
    """A Mermaid flowchart. Each zone is a subgraph (a trust boundary); flows crossing zones are dashed."""
    shape = {"external_entity": ("[", "]"), "process": ("((", "))"), "data_store": ("[(", ")]")}
    cross = crossings(arch)
    lines = ["flowchart LR"]
    for z in arch["zones"]:
        lines.append(f'  subgraph {z["id"]}["{z["name"]} ({z["trust"]})"]')
        for e in arch["elements"]:
            if e["zone"] == z["id"]:
                a, b = shape[e["type"]]
                lines.append(f'    {e["id"]}{a}"{e.get("name", e["id"])}"{b}')
        lines.append("  end")
    for f in arch["flows"]:
        arrow = "-.->" if f["id"] in cross else "-->"
        lines.append(f'  {f["source"]} {arrow}|"{f["id"]}"| {f["target"]}')
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("arch", nargs="?", default=str(DEFAULT_ARCH))
    ap.add_argument("--format", choices=["md", "json", "csv"], default="md")
    ap.add_argument("--mermaid", action="store_true", help="print a Mermaid DFD instead of findings")
    args = ap.parse_args(argv)
    arch = load_arch(args.arch)
    problems = validate(arch)
    if problems:
        print("\n".join(f"DFD problem: {p}" for p in problems), file=sys.stderr)
        return 2
    if args.mermaid:
        print(to_mermaid(arch), end="")
        return 0
    findings = find_threats(arch)
    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif args.format == "csv":
        print(to_csv(findings), end="")
    else:
        print(to_markdown(findings, arch), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
