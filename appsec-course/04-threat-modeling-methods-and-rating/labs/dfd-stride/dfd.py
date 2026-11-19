"""DFD as data, with trust boundaries, validation rules and a STRIDE-per-element generator.

A DFD (data flow diagram) has four element kinds plus trust boundaries:

* external entity (people or systems you do not control),
* process (your code),
* data store (database, file, queue, cache, log),
* data flow (an arrow between two of the above),
* trust boundary (here: a "zone" on each element; a flow that changes zone crosses it).

The generator walks every element and flow and emits the STRIDE letters that usually
apply (the Microsoft SDL "STRIDE per element" table). Flows that cross a trust boundary
are marked priority "boundary", because most real threats live there.

Standard library only. All data is fictional.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
          "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
PER_ELEMENT = {"external": "SR", "process": "STRIDE", "datastore": "TID", "flow": "TID"}
PROPERTY = {"S": "authentication", "T": "integrity", "R": "non-repudiation",
            "I": "confidentiality", "D": "availability", "E": "authorization"}
QUESTION = {
    "S": "Can someone pretend to be {name}?",
    "T": "Can someone change {name} or the data it handles?",
    "R": "Can {name} deny an action, or can an action through it go unrecorded?",
    "I": "Can {name} leak data to someone who should not see it?",
    "D": "Can someone make {name} unavailable or slow?",
    "E": "Can someone gain rights through {name} they should not have?",
}


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(dfd: dict) -> list[str]:
    """Structural rules that keep a DFD meaningful (classic DFD rules)."""
    errs: list[str] = []
    els = {e["id"]: e for e in dfd["elements"]}
    zones = set(dfd.get("zones", []))
    for e in dfd["elements"]:
        if e["type"] not in ("external", "process", "datastore"):
            errs.append(f"{e['id']}: BAD_TYPE {e['type']}")
        if e.get("zone") not in zones:
            errs.append(f"{e['id']}: UNKNOWN_ZONE")
    for f in dfd["flows"]:
        s, d = els.get(f["src"]), els.get(f["dst"])
        if s is None or d is None:
            errs.append(f"{f['id']}: DANGLING_FLOW")
            continue
        kinds = {s["type"], d["type"]}
        if s["type"] == d["type"] == "datastore":
            errs.append(f"{f['id']}: STORE_TO_STORE (data must move through a process)")
        elif s["type"] == d["type"] == "external":
            errs.append(f"{f['id']}: EXTERNAL_TO_EXTERNAL (out of scope for this model)")
        elif kinds == {"external", "datastore"}:
            errs.append(f"{f['id']}: EXTERNAL_TO_STORE (a process must sit between them)")
    for e in dfd["elements"]:
        if e["type"] != "process":
            continue
        ins = [f for f in dfd["flows"] if f["dst"] == e["id"]]
        outs = [f for f in dfd["flows"] if f["src"] == e["id"]]
        if not ins and outs:
            errs.append(f"{e['id']}: MIRACLE (output with no input)")
        if ins and not outs:
            errs.append(f"{e['id']}: BLACK_HOLE (input with no output)")
        if not ins and not outs:
            errs.append(f"{e['id']}: ISOLATED_PROCESS")
    return errs


def crossings(dfd: dict) -> list[str]:
    zone = {e["id"]: e["zone"] for e in dfd["elements"]}
    return [f["id"] for f in dfd["flows"] if zone.get(f["src"]) != zone.get(f["dst"])]


@dataclass
class Threat:
    target: str
    kind: str
    letter: str
    question: str
    priority: str

    @property
    def category(self) -> str:
        return STRIDE[self.letter]


def stride_per_element(dfd: dict) -> list[Threat]:
    out: list[Threat] = []
    cross = set(crossings(dfd))
    for e in dfd["elements"]:
        letters = PER_ELEMENT[e["type"]]
        if e["type"] == "datastore" and e.get("holds_logs"):
            letters += "R"
        for L in letters:
            out.append(Threat(e["id"], e["type"], L, QUESTION[L].format(name=e.get("label", e["id"])), "normal"))
    for f in dfd["flows"]:
        prio = "boundary" if f["id"] in cross else "normal"
        for L in PER_ELEMENT["flow"]:
            out.append(Threat(f["id"], "flow", L, QUESTION[L].format(name=f"flow {f['id']} ({f['label']})"), prio))
    return out


def summary(threats: list[Threat]) -> dict[str, int]:
    counts = {v: 0 for v in STRIDE.values()}
    for t in threats:
        counts[t.category] += 1
    return counts


def mermaid(dfd: dict) -> str:
    """Mermaid flowchart: one subgraph per trust zone; boundary-crossing flows are dashed."""
    shape = {"external": ('["', '"]'), "process": ('(("', '"))'), "datastore": ('[("', '")]')}
    lines = ["flowchart LR"]
    for z in dfd["zones"]:
        lines.append(f'  subgraph {z.replace("-", "_")}["Trust zone: {z}"]')
        for e in dfd["elements"]:
            if e["zone"] == z:
                a, b = shape[e["type"]]
                lines.append(f"    {e['id']}{a}{e.get('label', e['id'])}{b}")
        lines.append("  end")
    cross = set(crossings(dfd))
    for f in dfd["flows"]:
        arrow = "-.->" if f["id"] in cross else "-->"
        lines.append(f'  {f["src"]} {arrow}|"{f["id"]}: {f["label"]}"| {f["dst"]}')
    return "\n".join(lines)
