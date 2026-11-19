"""Read and validate an OWASP Threat Dragon v2-style model (JSON) offline.

The fixture follows the general SHAPE of Threat Dragon 2.x files as we understand it:
  {"version": "2.x", "summary": {...}, "detail": {"diagrams": [{"diagramType": "STRIDE", "cells": [...]}]}}
  each cell has "shape" and "data": {"type": "tm.Process" | "tm.Store" | "tm.Actor" | "tm.Flow" | "tm.Boundary",
  "name", "outOfScope", "reasonOutOfScope", "threats": [{"title", "type", "status", "severity", "mitigation"}]}
  flows have "source": {"cell": id} and "target": {"cell": id} and data flags isEncrypted / isPublicNetwork.
Field names change between versions: open a file saved by YOUR Threat Dragon version and adjust. Verify at source.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ELEMENT_TYPES = {"tm.Process", "tm.Store", "tm.Actor"}
STRIDE = {"spoofing", "tampering", "repudiation", "information disclosure", "denial of service",
          "elevation of privilege"}


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cells(model: dict) -> list[dict]:
    return [c for d in model["detail"]["diagrams"] for c in d.get("cells", [])]


def elements(model: dict) -> list[dict]:
    return [c for c in cells(model) if c.get("data", {}).get("type") in ELEMENT_TYPES]


def flows(model: dict) -> list[dict]:
    return [c for c in cells(model) if c.get("data", {}).get("type") == "tm.Flow"]


def validate(model: dict) -> list[str]:
    problems = []
    if not str(model.get("version", "")).startswith("2."):
        problems.append(f"model version {model.get('version')!r}: this checker expects Threat Dragon 2.x files")
    ids = {c["id"] for c in cells(model)}
    for c in elements(model) + flows(model):
        d, name = c["data"], c["data"].get("name", c["id"])
        threats = d.get("threats", [])
        if d.get("outOfScope"):
            if not d.get("reasonOutOfScope"):
                problems.append(f"{name}: out of scope without a reason")
            continue
        if not threats:
            problems.append(f"{name}: in scope but no threats recorded (not analysed?)")
        for t in threats:
            if str(t.get("type", "")).lower() not in STRIDE:
                problems.append(f"{name}: threat '{t.get('title')}' has non-STRIDE type {t.get('type')!r}")
            if str(t.get("status", "")).lower() == "mitigated" and not t.get("mitigation"):
                problems.append(f"{name}: threat '{t.get('title')}' is Mitigated but the mitigation is empty")
        open_ = any(str(t.get("status", "")).lower() == "open" for t in threats)
        if bool(d.get("hasOpenThreats")) != open_:
            problems.append(f"{name}: hasOpenThreats flag does not match the threat list")
    for f in flows(model):
        d = f["data"]
        for end in ("source", "target"):
            if f.get(end, {}).get("cell") not in ids:
                problems.append(f"{d.get('name')}: flow {end} points to a missing cell")
        if d.get("isPublicNetwork") and not d.get("isEncrypted"):
            problems.append(f"{d.get('name')}: crosses a public network unencrypted")
    return problems


def open_threats(model: dict, severity: str | None = None) -> list[tuple[str, str, str]]:
    out = []
    for c in elements(model) + flows(model):
        for t in c["data"].get("threats", []):
            if str(t.get("status", "")).lower() == "open" and (severity is None or t.get("severity") == severity):
                out.append((c["data"]["name"], t["type"], t["title"]))
    return out


def summary(model: dict) -> dict:
    all_t = [t for c in elements(model) + flows(model) for t in c["data"].get("threats", [])]
    return {"elements": len(elements(model)), "flows": len(flows(model)), "threats": len(all_t),
            "by_status": dict(Counter(str(t.get("status")) for t in all_t)),
            "by_type": dict(Counter(str(t.get("type")) for t in all_t))}
