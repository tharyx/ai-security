"""Model governance: approve models and model *versions* through gates, then let the
deployment pipeline run only the exact artifact that was approved.

An approval is for one artifact (pinned by its SHA-256), for one system, at one tier,
for a limited time. A new fine-tune, a new vendor model version or a silently swapped file
is a different artifact and needs its own approval.

Gates (finding codes)
    MA-01  version not pinned: 'latest' / missing version or a malformed artifact hash
    MA-02  documentation incomplete: the model card still has validator findings (doc_validator.py)
    MA-03  a required evaluation is missing or failed (required set grows with the tier)
    MA-04  high/critical tier with no linked risk-register entry, or the risk owner has not accepted it
    MA-05  third-party model with no vendor assessment, or one older than VENDOR_MAX_AGE_DAYS
    MA-06  a required approver role is missing (required roles grow with the tier)
    MA-07  separation of duties: the requester approved their own request in an oversight role
    MA-08  high/critical tier with no tested rollback plan

The deployment check (can_deploy) refuses an artifact whose hash differs from the approved
one, even if the version label is the same. That is how a silent model swap is caught.

Educational lab. The gate set and tiers are an example organizational policy that implements
"AI Model Approval Policy" (07-ai-governance/policies/03-ai-model-approval-policy.md).

    python 07-ai-governance/lab/model_approval.py 07-ai-governance/lab/fixtures/model_requests.yaml
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

HEX64 = re.compile(r"^[0-9a-f]{64}$")
VENDOR_MAX_AGE_DAYS = 365
REQUIRED_EVALS = {
    "low": {"quality"},
    "medium": {"quality", "security"},
    "high": {"quality", "security", "fairness"},
    "critical": {"quality", "security", "fairness"},
}
REQUIRED_ROLES = {
    "low": {"technical_owner"},
    "medium": {"technical_owner", "security"},
    "high": {"technical_owner", "security", "risk_owner"},
    "critical": {"technical_owner", "security", "risk_owner", "ai_governance_board"},
}
OVERSIGHT_ROLES = {"security", "risk_owner", "ai_governance_board", "privacy"}
APPROVAL_VALID_DAYS = {"low": 365, "medium": 365, "high": 180, "critical": 90}


@dataclass
class ApprovalDecision:
    request_id: str
    system_id: str
    model: str
    version: str
    artifact_sha256: str
    tier: str
    decision: str  # APPROVED | REJECTED
    findings: list[tuple[str, str]] = field(default_factory=list)
    valid_until: date | None = None


def assess_request(req: dict, as_of: date) -> ApprovalDecision:
    tier = req.get("tier", "critical")  # unknown tier is treated as the strictest
    if tier not in REQUIRED_ROLES:
        tier = "critical"
    d = ApprovalDecision(req.get("request_id", "?"), req.get("system_id", "?"), req.get("model", "?"),
                         str(req.get("version", "")), str(req.get("artifact_sha256", "")), tier, "REJECTED")
    add = lambda code, msg: d.findings.append((code, msg))  # noqa: E731

    if d.version.strip().lower() in {"", "latest", "stable", "default"} or not HEX64.match(d.artifact_sha256):
        add("MA-01", f"version '{d.version}' / hash not pinned to one artifact")

    if req.get("model_card_findings") is None or req.get("model_card_findings") > 0:
        add("MA-02", f"model card has {req.get('model_card_findings', 'unknown')} open validator finding(s)")

    evals = req.get("evals") or {}
    for etype in sorted(REQUIRED_EVALS[tier]):
        if evals.get(etype) != "pass":
            add("MA-03", f"{etype} evaluation is '{evals.get(etype, 'missing')}' (must be 'pass' for {tier})")

    if tier in {"high", "critical"} and (not req.get("risk_entry") or not req.get("risk_owner_accepted")):
        add("MA-04", "no linked risk entry accepted by its owner")

    if req.get("third_party", False):
        assessed = req.get("vendor_assessment_date")
        if not isinstance(assessed, date):
            add("MA-05", "third-party model with no vendor assessment")
        elif (as_of - assessed).days > VENDOR_MAX_AGE_DAYS:
            add("MA-05", f"vendor assessment from {assessed} is older than {VENDOR_MAX_AGE_DAYS} days")

    approvals = req.get("approvals") or []
    requester = str(req.get("requested_by", "")).lower()
    valid_roles = set()
    for a in approvals:
        role, name = a.get("role"), str(a.get("name", "")).lower()
        if role in OVERSIGHT_ROLES and name == requester:
            add("MA-07", f"requester '{requester}' approved their own request as '{role}'")
            continue
        valid_roles.add(role)
    missing = REQUIRED_ROLES[tier] - valid_roles
    if missing:
        add("MA-06", f"missing approval from: {', '.join(sorted(missing))}")

    if tier in {"high", "critical"} and not req.get("rollback_tested"):
        add("MA-08", "no tested rollback to the previous approved version")

    if not d.findings:
        d.decision = "APPROVED"
        d.valid_until = as_of + timedelta(days=APPROVAL_VALID_DAYS[tier])
    return d


def can_deploy(registry: list[ApprovalDecision], system_id: str, model: str, artifact_sha256: str,
               on: date) -> tuple[bool, str]:
    """The pipeline's question: may THIS artifact run for THIS system today?"""
    approved = [r for r in registry if r.decision == "APPROVED" and r.system_id == system_id and r.model == model]
    if not approved:
        return False, f"no approved version of {model} for {system_id}"
    exact = [r for r in approved if r.artifact_sha256 == artifact_sha256]
    if not exact:
        return False, "artifact hash differs from every approved artifact (silent swap or unapproved version)"
    if all(r.valid_until is None or on > r.valid_until for r in exact):
        return False, "approval expired: re-approve the model version"
    return True, f"approved ({exact[0].request_id}, valid until {exact[0].valid_until})"


def main() -> None:
    p = argparse.ArgumentParser(description="Assess model approval requests.")
    p.add_argument("requests", help="YAML list of approval requests")
    p.add_argument("--as-of", default="2026-11-15")
    args = p.parse_args()
    as_of = date.fromisoformat(args.as_of)
    for req in yaml.safe_load(Path(args.requests).read_text(encoding="utf-8")):
        d = assess_request(req, as_of)
        print(f"{d.request_id:8} {d.model:18} {d.version:9} {d.tier:8} {d.decision}")
        for code, msg in d.findings:
            print(f"{'':10}{code} {msg}")


if __name__ == "__main__":
    main()
