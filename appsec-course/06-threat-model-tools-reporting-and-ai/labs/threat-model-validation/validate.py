"""Validate a threat model: model versus reality, all threats accounted for, mitigations tested,
and "are we done?" exit criteria.

Inputs (JSON):
  model.json         components, flows (with boundary flag), threats (status, mitigation, tests, acceptance)
  inventory.json     what is really deployed (cloud inventory, Kubernetes services, API gateway routes)
                     and flows observed in network logs
  test_results.json  test id -> "pass" / "fail"
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path


def load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def model_vs_reality(model: dict, inventory: dict) -> list[str]:
    modeled = {c["name"] for c in model["components"]}
    deployed = {c["name"] for c in inventory["deployed"]}
    out = [f"SHADOW: {n} is deployed but not in the model" for n in sorted(deployed - modeled)]
    out += [f"STALE: {n} is in the model but not deployed" for n in sorted(modeled - deployed)]
    flows = {(f["from"], f["to"]) for f in model["flows"]}
    for f in inventory.get("observed_flows", []):
        if (f["from"], f["to"]) not in flows:
            out.append(f"UNMODELED FLOW: {f['from']} -> {f['to']} seen in {f['source']}")
    return out


def accounted_for(model: dict, today: date) -> list[str]:
    out = []
    for t in model["threats"]:
        st = t["status"]
        if st == "mitigated" and not t.get("mitigation"):
            out.append(f"{t['id']}: marked mitigated but no mitigation is described")
        elif st == "accepted":
            a = t.get("acceptance", {})
            if not all(a.get(k) for k in ("owner", "approved_by", "expires")):
                out.append(f"{t['id']}: accepted without owner, approver and expiry")
            elif date.fromisoformat(a["expires"]) < today:
                out.append(f"{t['id']}: risk acceptance expired on {a['expires']}")
        elif st == "transferred" and not t.get("transferred_to"):
            out.append(f"{t['id']}: transferred but to whom?")
        elif st not in ("mitigated", "accepted", "transferred", "not_applicable"):
            out.append(f"{t['id']}: status '{st}' is not a decision")
    covered = {t["target"] for t in model["threats"]}
    for c in model["components"]:
        if c["name"] not in covered:
            out.append(f"{c['name']}: component has no threats at all (was it analysed?)")
    for f in model["flows"]:
        name = f"{f['from']} -> {f['to']}"
        if f.get("crosses_boundary") and name not in covered:
            out.append(f"{name}: boundary-crossing flow has no threats")
    return out


def mitigations_tested(model: dict, results: dict) -> list[str]:
    out = []
    for t in model["threats"]:
        if t["status"] != "mitigated":
            continue
        tests = t.get("tests", [])
        if not tests:
            out.append(f"{t['id']}: mitigation '{t.get('mitigation', '')}' has no test")
        for test in tests:
            r = results.get(test)
            if r is None:
                out.append(f"{t['id']}: test {test} did not run")
            elif r != "pass":
                out.append(f"{t['id']}: test {test} FAILED, so the mitigation is not proven")
    return out


def are_we_done(model: dict, inventory: dict, results: dict, today: date) -> dict[str, bool]:
    return {
        "model matches what is deployed": not model_vs_reality(model, inventory),
        "every threat has a decision": not accounted_for(model, today),
        "every mitigation has a passing test": not mitigations_tested(model, results),
        "model reviewed for the deployed version": model.get("reviewed_version") == inventory.get("version"),
        "next review date set": bool(model.get("next_review")),
    }


def gate(done: dict[str, bool]) -> int:
    return 0 if all(done.values()) else 1
