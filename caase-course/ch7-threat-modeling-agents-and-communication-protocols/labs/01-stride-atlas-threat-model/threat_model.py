"""STRIDE + MITRE ATLAS + OWASP ASI threat model for a multi-agent deployment (Chapter 7, lab 1).

Reads deployment.yaml (zones, elements, flows) and threat_library.yaml, then:
  * validate()     - structural checks on the DFD
  * crossings()    - flows that cross a trust boundary (and the trust change)
  * find_threats() - STRIDE-per-element/flow, with ATLAS tactic and ASI id attached
  * score()        - agentic risk score: likelihood x impact x modifiers (autonomy, boundary, delegation)
Everything is data; no network and no model.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
STRIDE = "STRIDE"
# classic STRIDE-per-element table
APPLIES = {
    "external_entity": "SR",
    "process": "STRIDE",
    "data_store": "TRID",
    "data_flow": "TID",
}
AUTONOMY = {"low": 1.0, "medium": 1.15, "high": 1.3}


def load(path: Path | None = None, library: Path | None = None) -> tuple[dict, list[dict]]:
    arch = yaml.safe_load((path or HERE / "deployment.yaml").read_text(encoding="utf-8"))
    lib = yaml.safe_load((library or HERE / "threat_library.yaml").read_text(encoding="utf-8"))["threats"]
    return arch, lib


def validate(arch: dict) -> list[str]:
    problems: list[str] = []
    ids = {e["id"]: e for e in arch["elements"]}
    for e in arch["elements"]:
        if e["zone"] not in arch["zones"]:
            problems.append(f"element {e['id']}: unknown zone {e['zone']}")
    for f in arch["flows"]:
        for end in ("source", "target"):
            if f[end] not in ids:
                problems.append(f"flow {f['id']}: unknown {end} {f[end]}")
        if f["source"] in ids and f["target"] in ids:
            if ids[f["source"]]["type"] != "process" and ids[f["target"]]["type"] != "process":
                problems.append(f"flow {f['id']}: one end of every flow must be a process")
    return problems


def crossings(arch: dict) -> dict[str, int]:
    """flow id -> trust change (positive = data flows from a LOWER zone into a HIGHER one)."""
    ids = {e["id"]: e for e in arch["elements"]}
    out = {}
    for f in arch["flows"]:
        a, b = ids[f["source"]]["zone"], ids[f["target"]]["zone"]
        if a != b:
            out[f["id"]] = arch["zones"][b]["trust"] - arch["zones"][a]["trust"]
    return out


@dataclass
class Finding:
    id: str
    element: str
    kind: str
    stride: str
    title: str
    atlas: str
    asi: str
    protocol: str
    crossing: bool
    score: float
    control: str


def score(threat: dict, element: dict | None, crossing_gain: int, delegation_depth: int = 1) -> float:
    """Agentic scoring: base = likelihood x impact (1-25), then multiply.

    * autonomy of the acting agent (high autonomy = fewer humans in the loop)
    * x1.25 if the path moves data into a HIGHER-trust zone (untrusted data moving up)
    * +10% per extra delegation hop (capped at +30%)
    """
    base = threat["impact"] * threat["likelihood"]
    mult = AUTONOMY.get((element or {}).get("autonomy", "low"), 1.0)
    if crossing_gain > 0:
        mult *= 1.25
    mult *= 1 + min(0.3, 0.1 * (delegation_depth - 1))
    return round(base * mult, 1)


def _touches(arch: dict, element_id: str, protocol: str) -> bool:
    for f in arch["flows"]:
        if f.get("protocol") == protocol and element_id in (f["source"], f["target"], f["id"]):
            return True
    return False


def find_threats(arch: dict, lib: list[dict] | None = None) -> list[Finding]:
    if lib is None:
        _, lib = load()
    ids = {e["id"]: e for e in arch["elements"]}
    cross = crossings(arch)
    targets: list[tuple[str, str, dict | None, str, bool, int]] = []
    for e in arch["elements"]:
        targets.append((e["id"], e["type"], e, "-", False, 0))
    for f in arch["flows"]:
        targets.append((f["id"], "data_flow", ids[f["target"]], f.get("protocol", "-"),
                        f["id"] in cross, cross.get(f["id"], 0)))
    findings: list[Finding] = []
    n = 0
    for tid, kind, el, proto, is_cross, gain in targets:
        for t in lib:
            if kind not in t["kinds"] or t["stride"] not in APPLIES[kind]:
                continue
            if t["id"] in ("T-DISCOVERY", "T-REPLAY", "T-DOWNGRADE") and proto not in ("a2a", "acp_style", "ucp_style", "mcp"):
                continue
            if t["id"] == "T-EOP-SESSION" and not _touches(arch, tid, "acp_style"):
                continue
            if t["id"] in ("T-TAMPER-CTX", "T-LEAK-CTX") and not _touches(arch, tid, "ucp_style"):
                continue
            n += 1
            findings.append(Finding(
                id=f"TM-{n:03d}", element=tid, kind=kind, stride=t["stride"], title=t["title"],
                atlas=t["atlas"], asi=t["asi"], protocol=proto, crossing=is_cross,
                score=score(t, el, gain), control=t["control"]))
    return sorted(findings, key=lambda x: -x.score)


def summary(findings: list[Finding]) -> dict:
    by_stride = {k: 0 for k in STRIDE}
    for f in findings:
        by_stride[f.stride] += 1
    return {"total": len(findings), "by_stride": by_stride,
            "critical": sum(1 for f in findings if f.score >= 25),
            "atlas_tactics": sorted({f.atlas for f in findings}),
            "asi_ids": sorted({f.asi for f in findings})}


def to_markdown(findings: list[Finding], top: int = 15) -> str:
    rows = ["| ID | Element | STRIDE | Threat | ATLAS tactic | ASI | Score |", "|---|---|---|---|---|---|---|"]
    for f in findings[:top]:
        rows.append(f"| {f.id} | {f.element} | {f.stride} | {f.title} | {f.atlas} | {f.asi} | {f.score} |")
    return "\n".join(rows)


if __name__ == "__main__":
    a, library = load()
    print(to_markdown(find_threats(a, library)))
