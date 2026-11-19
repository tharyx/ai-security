"""Privacy threat modeling with LINDDUN plus a PIA/DPIA screening, as code.

LINDDUN categories (KU Leuven; the 2023 update merges Unawareness and Unintervenability, verify):
  Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance.

The rules below are a teaching subset. A real LINDDUN session walks every element and flow with the
LINDDUN threat trees or the LINDDUN GO cards. Legal thresholds are simplified: check GDPR Art. 35,
your regulator's DPIA list and India's DPDP Act 2023 / DPDP Rules 2025 with your privacy team.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

LINDDUN = ["Linking", "Identifying", "Non-repudiation", "Detecting", "Data disclosure", "Unawareness",
           "Non-compliance"]
PERSONAL = {"personal", "sensitive", "identifier"}

REQUIREMENTS = {
    "Linking": "PRIV-01 Use per-recipient pseudonymous ids; never share one persistent id with several parties",
    "Identifying": "PRIV-02 Pseudonymise or aggregate data used for analytics and logs",
    "Non-repudiation": "PRIV-03 Do not keep signed, identity-linked records of sensitive user actions unless the law needs them",
    "Detecting": "PRIV-04 Give the same response whether or not an account exists",
    "Data disclosure": "PRIV-05 Collect only data with a stated purpose, set retention, encrypt in transit",
    "Unawareness": "PRIV-06 Show a clear notice, record consent, support access, correction and deletion requests",
    "Non-compliance": "PRIV-07 Keep a record of processing, a DPIA when required, and safeguards for transfers abroad",
}

# DPIA screening criteria (after the EDPB/WP29 guidelines; two or more usually means "do a DPIA").
DPIA_CRITERIA = {
    "evaluation_or_scoring": "Evaluation, scoring or profiling",
    "automated_decisions": "Automated decisions with legal or similar significant effect",
    "systematic_monitoring": "Systematic monitoring",
    "sensitive_data": "Sensitive (special category) data",
    "large_scale": "Processing at large scale",
    "matching_datasets": "Matching or combining datasets",
    "vulnerable_subjects": "Data about vulnerable people (for example children, patients)",
    "new_technology": "Innovative use of new technology",
    "blocks_rights_or_service": "Processing that stops people using a service or exercising a right",
}


@dataclass
class Threat:
    category: str
    target: str
    text: str


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def linddun(system: dict) -> list[Threat]:
    data = {d["name"]: d for d in system["data"]}
    flows, feat = system["flows"], system.get("features", {})
    out: list[Threat] = []

    # Linking: one persistent identifier sent to two or more different recipients
    for d in data.values():
        if d["category"] == "identifier":
            recipients = {f["to"] for f in flows if d["name"] in f["data"] and f.get("third_party")}
            if len(recipients) >= 2:
                out.append(Threat("Linking", d["name"], f"same id shared with {sorted(recipients)}: profiles can be joined"))
    # Identifying: personal data reaches analytics or logs without pseudonymisation
    for f in flows:
        personal = [x for x in f["data"] if data[x]["category"] in PERSONAL]
        if f.get("purpose") in ("analytics", "logging") and personal and not f.get("pseudonymised"):
            out.append(Threat("Identifying", f["name"], f"{personal} sent for {f['purpose']} in identifiable form"))
    # Non-repudiation (unwanted): sensitive actions in signed, identity-linked logs
    if feat.get("signed_activity_log_of_sensitive_actions"):
        out.append(Threat("Non-repudiation", "activity log", "users cannot plausibly deny sensitive actions"))
    # Detecting: the system reveals whether a person is a member
    if feat.get("reveals_account_existence"):
        out.append(Threat("Detecting", "signup/reset", "responses reveal whether an email has an account"))
    # Data disclosure: no purpose, no retention, unencrypted personal flows
    for d in data.values():
        if d["category"] in PERSONAL and not d.get("purpose"):
            out.append(Threat("Data disclosure", d["name"], "collected without a stated purpose (minimisation)"))
        if d["category"] in PERSONAL and not d.get("retention_days"):
            out.append(Threat("Data disclosure", d["name"], "no retention period: kept forever"))
    for f in flows:
        if any(data[x]["category"] in PERSONAL for x in f["data"]) and not f.get("encrypted"):
            out.append(Threat("Data disclosure", f["name"], "personal data sent without encryption"))
    # Unawareness (and unintervenability)
    for key, text in (("privacy_notice", "no privacy notice"), ("consent_records", "consent is not recorded"),
                      ("access_and_deletion_requests", "users cannot see or delete their data")):
        if not feat.get(key):
            out.append(Threat("Unawareness", "user", text))
    # Non-compliance
    if not feat.get("record_of_processing"):
        out.append(Threat("Non-compliance", "organisation", "no record of processing activities"))
    for f in flows:
        if f.get("cross_border") and not f.get("transfer_safeguards"):
            out.append(Threat("Non-compliance", f["name"], "transfer abroad without checked safeguards"))
    if dpia_screening(system)["required"] and not feat.get("dpia_done"):
        out.append(Threat("Non-compliance", "organisation", "DPIA required but not done"))
    return out


def dpia_screening(system: dict) -> dict:
    hits = [DPIA_CRITERIA[k] for k in DPIA_CRITERIA if system.get("processing", {}).get(k)]
    return {"required": len(hits) >= 2, "criteria_met": hits}


def privacy_requirements(threats: list[Threat]) -> list[str]:
    cats = {t.category for t in threats}
    return [REQUIREMENTS[c] for c in LINDDUN if c in cats]


def summary(threats: list[Threat]) -> dict[str, int]:
    return {c: sum(t.category == c for t in threats) for c in LINDDUN}
