"""Compliance as code and audit as code for a PCI DSS v4.0.1 cardholder-data system (teaching subset).

* Rules are DATA (fixtures/pci_rules.json): requirement id, path into the config, operator, expected value.
* The engine has a fixed set of operators: no eval, so a rule file cannot run code.
* Waivers (compensating controls) are per system and need a reason, an owner and an expiry date;
  expired or incomplete waivers fail.
* The evidence bundle is "audit as code": results plus a SHA-256 of the exact config that was checked,
  so an auditor can re-run the check and detect a config that changed after the scan.

Requirement numbers follow PCI DSS v4.0.1 as we understand it; the titles are paraphrases.
Verify numbering and wording in the PCI SSC document library and with your QSA.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

MISSING = object()


def get_path(config: dict, path: str):
    obj = config
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return MISSING
        obj = obj[part]
    return obj


def _no_item_matches(items, cond: dict) -> bool:
    return not any(all(item.get(k) == v for k, v in cond.items()) for item in items or [])


OPS = {
    "eq": lambda v, e: v == e,
    "gte": lambda v, e: isinstance(v, (int, float)) and v >= e,
    "lte": lambda v, e: isinstance(v, (int, float)) and v <= e,
    "between": lambda v, e: isinstance(v, (int, float)) and e[0] <= v <= e[1],
    "in": lambda v, e: v in e,
    "matches": lambda v, e: isinstance(v, str) and re.fullmatch(e, v) is not None,
    "no_item_matches": _no_item_matches,
}


@dataclass
class Result:
    rule_id: str
    requirement: str
    title: str
    status: str  # PASS, FAIL, WAIVED
    observed: object
    detail: str = ""


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(rules: list[dict], config: dict, waivers: list[dict] | None = None,
             today: date | None = None) -> list[Result]:
    today = today or date.today()
    system = config.get("system")
    waivers = {w["rule_id"]: w for w in (waivers or []) if w.get("system", system) == system}
    out = []
    for r in rules:
        if r["op"] not in OPS:
            raise ValueError(f"{r['id']}: unknown operator {r['op']!r}")
        observed = get_path(config, r["path"])
        ok = observed is not MISSING and OPS[r["op"]](observed, r["expected"])
        shown = "<missing>" if observed is MISSING else observed
        status, detail = ("PASS", "") if ok else ("FAIL", f"expected {r['op']} {r['expected']!r}")
        w = waivers.get(r["id"])
        if not ok and w:
            if not all(w.get(k) for k in ("reason", "owner", "expires")):
                detail += "; waiver ignored: needs reason, owner and expires"
            elif date.fromisoformat(w["expires"]) < today:
                detail += f"; waiver expired on {w['expires']}"
            else:
                status, detail = "WAIVED", f"compensating control until {w['expires']}: {w['reason']}"
        out.append(Result(r["id"], r["requirement"], r["title"], status, shown, detail))
    return out


def gate(results: list[Result]) -> int:
    return 1 if any(r.status == "FAIL" for r in results) else 0


def config_digest(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def evidence_bundle(results: list[Result], config: dict, system: str, when: str) -> dict:
    return {
        "system": system,
        "checked_at": when,
        "standard": "PCI DSS v4.0.1 (subset; verify at PCI SSC)",
        "config_sha256": config_digest(config),
        "summary": {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "WAIVED")},
        "results": [r.__dict__ for r in results],
    }


def verify_evidence(bundle: dict, config: dict) -> bool:
    """An auditor re-hashes the config: if it changed after the scan, the evidence is stale."""
    return bundle["config_sha256"] == config_digest(config)
