"""Component intake workflow: request form -> checks -> approve / conditional / reject + audit record.

All intelligence comes from fixture data (a JSON file standing in for Scorecard, an
advisory database, registry metadata and license data). No network. The malicious-package
check is a STUB with a few cheap heuristics: real tools (GuardDog, behaviour sandboxes,
Socket-style services) do much more. Fixture packages are fictional.
"""
from __future__ import annotations

import difflib
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date

import yaml

APPROVE, CONDITIONAL, REJECT = "approve", "conditional", "reject"
COMPONENT_TYPES = {"open_source", "commercial", "third_party", "proprietary"}
REQUIRED_FIELDS = ["name", "version", "component_type", "requester", "justification", "use"]

POPULAR = ["requests", "numpy", "pandas", "lodash", "express", "react", "django", "flask",
           "urllib3", "colorama", "cryptography", "pyyaml"]

# Example license policy (an organisation sets its own; this is not legal advice).
LICENSE_ALLOW = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"}
LICENSE_REVIEW = {"MPL-2.0", "LGPL-3.0", "EPL-2.0", "GPL-2.0", "GPL-3.0"}
LICENSE_DENY = {"AGPL-3.0", "SSPL-1.0", "UNLICENSED", "NONE"}

# Scorecard-like check weights (the real Scorecard weights risk levels; verify at source).
SCORECARD_WEIGHTS = {"Maintained": 3, "Code-Review": 3, "Branch-Protection": 2, "Vulnerabilities": 3,
                     "Dangerous-Workflow": 3, "Pinned-Dependencies": 1, "Signed-Releases": 1,
                     "Security-Policy": 1, "Token-Permissions": 2, "License": 1}


@dataclass
class Finding:
    check: str
    status: str            # pass | condition | fail
    detail: str = ""


@dataclass
class Decision:
    request: dict
    outcome: str
    findings: list[Finding] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    score: float | None = None


def load_request(text: str) -> dict:
    return yaml.safe_load(text)


def scorecard_score(checks: dict) -> float | None:
    """Weighted average on a 0-10 scale; -1 means 'not applicable' and is skipped."""
    num = den = 0.0
    for name, val in (checks or {}).items():
        if val is None or val < 0:
            continue
        w = SCORECARD_WEIGHTS.get(name, 1)
        num += w * val
        den += w
    return round(num / den, 1) if den else None


def edit_distance_close(name: str) -> str | None:
    for pop in POPULAR:
        if name != pop and difflib.SequenceMatcher(None, name, pop).ratio() >= 0.85:
            return pop
    return None


# --- individual checks -------------------------------------------------------

def check_form(req: dict) -> list[Finding]:
    missing = [f for f in REQUIRED_FIELDS if not req.get(f)]
    if missing:
        return [Finding("form", "fail", f"missing fields: {', '.join(missing)}")]
    if req["component_type"] not in COMPONENT_TYPES:
        return [Finding("form", "fail", f"unknown component_type {req['component_type']!r}")]
    return [Finding("form", "pass", "complete")]


def check_license(intel: dict, req: dict) -> Finding:
    lic = (intel.get("license") or "NONE").strip()
    if lic in LICENSE_DENY:
        return Finding("license", "fail", f"{lic} is denied by policy")
    if lic in LICENSE_REVIEW:
        return Finding("license", "condition", f"{lic} needs legal review before shipping")
    if lic in LICENSE_ALLOW:
        return Finding("license", "pass", lic)
    return Finding("license", "condition", f"unknown license {lic!r}: legal review")


def check_vulns(intel: dict, req: dict) -> Finding:
    version = req["version"]
    bad = [v for v in intel.get("vulnerabilities", []) if version in v.get("affected_versions", [])]
    if not bad:
        return Finding("vulnerabilities", "pass", "no known advisories for this version")
    kev = [v for v in bad if v.get("kev")]
    crit = [v for v in bad if v["severity"] in ("critical", "high")]
    fixes = sorted({v["fixed_in"] for v in bad if v.get("fixed_in")})
    if kev:
        return Finding("vulnerabilities", "fail", f"known-exploited: {kev[0]['id']}")
    if crit and not all(v.get("fixed_in") for v in crit):
        return Finding("vulnerabilities", "fail", f"{crit[0]['id']} ({crit[0]['severity']}) has no fix")
    if crit:
        return Finding("vulnerabilities", "condition", f"use a fixed version: {fixes[-1]} or later")
    return Finding("vulnerabilities", "condition", "only low/medium advisories: track in the backlog")


def check_maintainers(intel: dict, today: date) -> Finding:
    m = intel.get("maintainers") or {}
    last = date.fromisoformat(m["last_release"]) if m.get("last_release") else None
    issues = []
    if last is None or (today - last).days > 365:
        issues.append("no release in over a year")
    if m.get("active_maintainers", 0) < 2:
        issues.append("single active maintainer (bus factor 1)")
    if m.get("owner_changed_days_ago") is not None and m["owner_changed_days_ago"] < 90:
        issues.append("ownership changed in the last 90 days")
    if not issues:
        return Finding("maintainer_health", "pass", "active and shared")
    status = "fail" if "ownership changed in the last 90 days" in issues and len(issues) > 1 else "condition"
    return Finding("maintainer_health", status, "; ".join(issues))


def check_malicious_stub(intel: dict, req: dict) -> Finding:
    reasons = []
    near = edit_distance_close(req["name"])
    if near:
        reasons.append(f"name is very close to popular package {near!r} (typosquat?)")
    meta = intel.get("package_meta") or {}
    if meta.get("has_install_script") and meta.get("network_at_install"):
        reasons.append("install script reaches the network")
    if meta.get("obfuscated_code"):
        reasons.append("obfuscated code in the package")
    if meta.get("age_days") is not None and meta["age_days"] < 30:
        reasons.append("package is less than 30 days old")
    if not reasons:
        return Finding("malicious_heuristics", "pass", "no heuristic fired (this is not proof)")
    hard = near or meta.get("obfuscated_code") or (meta.get("has_install_script") and meta.get("network_at_install"))
    return Finding("malicious_heuristics", "fail" if hard else "condition", "; ".join(reasons))


def check_scorecard(intel: dict) -> tuple[Finding, float | None]:
    score = scorecard_score(intel.get("scorecard") or {})
    if score is None:
        return Finding("scorecard", "condition", "no Scorecard data: manual review"), None
    if score < 4:
        return Finding("scorecard", "fail", f"score {score}/10 is below 4"), score
    if score < 6:
        return Finding("scorecard", "condition", f"score {score}/10: compensating controls"), score
    return Finding("scorecard", "pass", f"score {score}/10"), score


def check_by_type(intel: dict, req: dict) -> list[Finding]:
    ctype = req["component_type"]
    ev = intel.get("evidence") or {}
    out = []
    if ctype == "commercial":
        need = {"vendor_sbom": "vendor SBOM", "psirt_contact": "PSIRT / vulnerability contact",
                "security_attestation": "SOC 2 / ISO 27001 or secure-development attestation"}
        for key, label in need.items():
            out.append(Finding(f"commercial:{key}", "pass" if ev.get(key) else "condition",
                               f"{label} {'provided' if ev.get(key) else 'missing: request from vendor'}"))
    elif ctype == "third_party":
        for key, label in {"contract_security_clause": "security clause in the contract",
                           "sbom_on_delivery": "SBOM delivered with each release"}.items():
            out.append(Finding(f"third_party:{key}", "pass" if ev.get(key) else "condition", label))
    elif ctype == "proprietary":
        for key, label in {"code_review_enforced": "branch protection with required review",
                           "sast_clean": "SAST gate in the pipeline",
                           "signed_builds": "builds produce signed provenance"}.items():
            out.append(Finding(f"proprietary:{key}", "pass" if ev.get(key) else "condition", label))
    return out


# --- engine and audit --------------------------------------------------------

def vet(req: dict, intel_db: dict, today: date) -> Decision:
    findings = check_form(req)
    if findings[0].status == "fail":
        return Decision(req, REJECT, findings)
    intel = intel_db.get(req["name"])
    if intel is None and req["component_type"] == "open_source":
        findings.append(Finding("intel", "condition", "unknown to intel sources: manual review"))
        intel = {}
    intel = intel or {}
    if req["component_type"] == "open_source" or intel.get("scorecard"):
        sc, score = check_scorecard(intel)
        findings.append(sc)
    else:
        score = None
    findings += [check_license(intel, req), check_vulns(intel, req), check_maintainers(intel, today),
                 check_malicious_stub(intel, req)]
    findings += check_by_type(intel, req)
    if any(f.status == "fail" for f in findings):
        outcome = REJECT
    elif any(f.status == "condition" for f in findings):
        outcome = CONDITIONAL
    else:
        outcome = APPROVE
    conditions = [f"{f.check}: {f.detail}" for f in findings if f.status == "condition"]
    return Decision(req, outcome, findings, conditions, score)


class AuditLog:
    """Append-only JSON lines with a hash chain, so edits to old records are detectable."""

    def __init__(self, path: str):
        self.path = path

    def _last_hash(self) -> str:
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return "0" * 64
        return json.loads(lines[-1])["hash"] if lines else "0" * 64

    def record(self, d: Decision, when: date, reviewer: str = "auto-engine") -> dict:
        body = {"date": when.isoformat(), "component": f"{d.request.get('name')}@{d.request.get('version')}",
                "type": d.request.get("component_type"), "requester": d.request.get("requester"),
                "outcome": d.outcome, "score": d.score, "reviewer": reviewer,
                "findings": [[f.check, f.status, f.detail] for f in d.findings],
                "conditions": d.conditions, "prev": self._last_hash()}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True) + "\n")
        return body

    def verify_chain(self) -> bool:
        prev = "0" * 64
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                h = rec.pop("hash")
                if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
                    return False
                prev = h
        return True
