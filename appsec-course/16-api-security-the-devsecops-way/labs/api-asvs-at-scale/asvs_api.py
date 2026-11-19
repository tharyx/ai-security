"""API-focused ASVS checklists for a whole portfolio of APIs, with automated evidence.

Chapter 02's lab builds ONE checklist for ONE app. This lab does what a security champion needs
at scale:
  1. `checklist_for(api)`: pick ASVS-like requirements by the API's level and features
     (jwt, oauth, graphql, soap, webhooks, file-upload, public).
  2. `evaluate(api, evidence)`: mark each requirement pass / fail / untested / manual, using the
     results of automated checks the pipeline produced (SAST rule ids, DAST alerts, tests).
  3. `inventory_findings(inventory)`: hygiene problems that break security at scale
     (no owner, no OpenAPI spec, not behind the gateway, deprecated but live, stale deploys).
  4. `portfolio(inventory, evidence)`: one row per API with coverage and a gate.

The requirement texts in the fixture are short paraphrases and the `ref` values are SAMPLE
references grouped by ASVS 5.0 chapter names (verify chapter names and real ids at the source).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


def load(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


@dataclass
class Item:
    ref: str
    chapter: str
    level: int
    text: str
    verify_by: list[str]
    status: str = "untested"
    evidence: str = ""


def checklist_for(api: dict, requirements: list[dict]) -> list[Item]:
    feats = set(api.get("features", [])) | {"all"}
    out = []
    for r in requirements:
        if r["level"] <= api["level"] and feats & set(r["features"]):
            out.append(Item(r["ref"], r["chapter"], r["level"], r["text"], list(r["verify_by"])))
    return out


def evaluate(api: dict, requirements: list[dict], evidence: dict) -> list[Item]:
    """evidence: {check_name: "pass" | "fail"} produced by the pipeline for this API."""
    items = checklist_for(api, requirements)
    for it in items:
        automated = [c for c in it.verify_by if c != "manual"]
        results = {c: evidence.get(c) for c in automated}
        if any(v == "fail" for v in results.values()):
            it.status = "fail"
            it.evidence = ", ".join(c for c, v in results.items() if v == "fail")
        elif automated and all(v == "pass" for v in results.values()):
            it.status = "pass"
            it.evidence = ", ".join(automated)
        elif not automated:
            it.status = "manual"
            it.evidence = evidence.get(f"manual:{it.ref}", "")
            if it.evidence:
                it.status = "pass"
        else:
            it.status = "untested"
            it.evidence = "missing: " + ", ".join(c for c, v in results.items() if v is None)
    return items


def coverage(items: list[Item]) -> dict:
    n = len(items)
    done = sum(i.status in ("pass", "fail") for i in items)
    return {"requirements": n, "pass": sum(i.status == "pass" for i in items),
            "fail": sum(i.status == "fail" for i in items),
            "untested": sum(i.status == "untested" for i in items),
            "manual": sum(i.status == "manual" for i in items),
            "verified_pct": round(100 * done / n) if n else 100}


def gate(items: list[Item]) -> int:
    """Fail on any failed requirement, or any untested L1 requirement."""
    return 1 if any(i.status == "fail" or (i.status == "untested" and i.level == 1) for i in items) else 0


def inventory_findings(inventory: list[dict], today_year: int = 2026) -> list[str]:
    f = []
    for a in inventory:
        n = a["name"]
        if not a.get("owner"):
            f.append(f"{n}: no owning team (nobody fixes its findings)")
        if not a.get("spec"):
            f.append(f"{n}: no OpenAPI/GraphQL/WSDL contract in the repo (cannot DAST-scan or diff it)")
        if not a.get("behind_gateway"):
            f.append(f"{n}: not behind the API gateway (no central auth, rate limits, headers)")
        if a.get("deprecated") and a.get("live"):
            f.append(f"{n}: deprecated but still live (zombie API)")
        if a.get("last_deploy_year", today_year) < today_year - 2:
            f.append(f"{n}: last deployed {a['last_deploy_year']} (unpatched dependencies likely)")
    return f


def portfolio(inventory: list[dict], requirements: list[dict], evidence: dict) -> list[dict]:
    rows = []
    for a in inventory:
        items = evaluate(a, requirements, evidence.get(a["name"], {}))
        rows.append({"api": a["name"], "level": a["level"], **coverage(items), "gate": gate(items)})
    return rows


def to_markdown(api: dict, items: list[Item]) -> str:
    lines = [f"# ASVS checklist: {api['name']} (L{api['level']})", "",
             "| Ref | Chapter | L | Requirement | Status | Evidence |", "|---|---|---|---|---|---|"]
    for i in items:
        lines.append(f"| {i.ref} | {i.chapter} | {i.level} | {i.text} | {i.status} | {i.evidence} |")
    return "\n".join(lines)
