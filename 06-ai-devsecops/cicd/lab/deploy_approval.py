"""Deployment approval check: the last gate before an AI release reaches production.

Two questions, both answered from records instead of trust:

1. Is the production ENVIRONMENT protected?  (ENV-001 ... ENV-005)
   The settings are modeled on the shape GitHub returns for a deployment environment
   (required reviewers, prevent self-review, branch policy, admin bypass, environment
   secrets). Check the exact field names in the GitHub REST docs for your version.
2. Is THIS deployment properly approved?      (APR-001 ... APR-006)
   A human approved, the approver is not the person who started the release, the approver
   is in the approver group, the approval came after the release gate passed, it names the
   exact digest being deployed, and it is not stale.

    python deploy_approval.py --environment fixtures/env-production.good.json \
        --approval fixtures/approval.good.json --gate fixtures/gate-result.good.json \
        --deploy-digest sha256:... [--now 2026-11-18T12:00:00Z]

Exit code 0 = deploy may proceed, 1 = blocked. Missing evidence is a failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

CHECKS = {
    "ENV-001": ("HIGH", "Production environment requires reviewers"),
    "ENV-002": ("HIGH", "Self-review is prevented"),
    "ENV-003": ("HIGH", "Only protected branches can deploy"),
    "ENV-004": ("MEDIUM", "Administrators cannot bypass protection"),
    "ENV-005": ("HIGH", "No long-lived cloud keys stored as environment secrets"),
    "APR-001": ("HIGH", "A recorded human approval exists"),
    "APR-002": ("CRITICAL", "Approver is not the person who started the release"),
    "APR-003": ("HIGH", "Approver belongs to the approver group"),
    "APR-004": ("CRITICAL", "Approval, release gate and deploy name the same digest"),
    "APR-005": ("HIGH", "Approval came after a passing release gate"),
    "APR-006": ("MEDIUM", "Approval is fresh"),
}
LONG_LIVED = re.compile(r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS"
                        r"|GCP_SA_KEY|GOOGLE_CREDENTIALS", re.I)
DEFAULT_POLICY = {"min_reviewers": 1, "max_approval_age_hours": 24}


@dataclass
class Result:
    failures: dict[str, str]

    @property
    def passed(self) -> bool:
        return not self.failures


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_environment(env: dict, policy: dict) -> dict[str, str]:
    fails: dict[str, str] = {}
    rules = {r.get("type"): r for r in env.get("protection_rules") or []}
    reviewers = (rules.get("required_reviewers") or {}).get("reviewers") or []
    if len(reviewers) < policy["min_reviewers"]:
        fails["ENV-001"] = f"{len(reviewers)} reviewer entries, need {policy['min_reviewers']}"
    if not (rules.get("required_reviewers") or {}).get("prevent_self_review", False):
        fails["ENV-002"] = "prevent_self_review is not enabled"
    branch = env.get("deployment_branch_policy")
    if not branch or not (branch.get("protected_branches") or branch.get("custom_branch_policies")):
        fails["ENV-003"] = "any branch can deploy to this environment"
    if env.get("can_admins_bypass", True):
        fails["ENV-004"] = "admins can bypass (or the setting is unknown)"
    bad = [s for s in env.get("secrets") or [] if LONG_LIVED.search(s)]
    if bad:
        fails["ENV-005"] = f"long-lived cloud credentials as secrets: {bad}; use OIDC"
    return fails


def check_approval(env: dict, approval: dict | None, gate: dict | None, deploy_digest: str,
                   now: datetime, policy: dict) -> dict[str, str]:
    fails: dict[str, str] = {}
    if not approval or approval.get("state") != "approved" or not approval.get("approved_by"):
        fails["APR-001"] = "no approved review recorded"
        approval = approval or {}
    approver, starter = approval.get("approved_by", ""), approval.get("triggered_by", "")
    if not approver or approver == starter or approver in (approval.get("commit_authors") or []):
        fails["APR-002"] = f"approved by '{approver or 'nobody'}', release started by '{starter}'"
    if approver not in (env.get("reviewer_members") or []):
        fails["APR-003"] = f"'{approver or 'nobody'}' is not in the approver group"
    digests = {"approval": approval.get("digest"), "gate": (gate or {}).get("image_digest"), "deploy": deploy_digest}
    if len(set(digests.values())) != 1 or not deploy_digest:
        fails["APR-004"] = "digest mismatch: " + ", ".join(f"{k}={str(v)[:19]}" for k, v in digests.items())
    try:
        gate_ok = (gate or {}).get("decision") == "APPROVED"
        if not gate_ok or parse_time(approval["approved_at"]) < parse_time(gate["generated_at"]):
            fails["APR-005"] = "gate did not pass, or the approval is older than the gate evidence"
    except (KeyError, TypeError, ValueError):
        fails["APR-005"] = "missing gate or approval timestamps"
    try:
        age_h = (now - parse_time(approval["approved_at"])).total_seconds() / 3600
        if not 0 <= age_h <= policy["max_approval_age_hours"]:
            fails["APR-006"] = f"approval is {age_h:.1f} hours old"
    except (KeyError, ValueError):
        fails["APR-006"] = "approval has no valid approved_at"
    return fails


def evaluate(env: dict, approval: dict | None, gate: dict | None, deploy_digest: str, *,
             now: datetime | None = None, policy: dict | None = None) -> Result:
    policy = {**DEFAULT_POLICY, **(policy or {})}
    now = now or datetime.now(timezone.utc)
    fails = check_environment(env, policy)
    fails.update(check_approval(env, approval, gate, deploy_digest, now, policy))
    return Result(fails)


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deployment approval check")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--deploy-digest", required=True)
    parser.add_argument("--now")
    args = parser.parse_args(argv)
    now = parse_time(args.now) if args.now else datetime.now(timezone.utc)
    result = evaluate(load_json(args.environment), load_json(args.approval), load_json(args.gate),
                      args.deploy_digest, now=now)
    for check_id, (sev, title) in CHECKS.items():
        detail = result.failures.get(check_id)
        print(f"{'FAIL' if detail else 'ok  '}  {check_id}  {sev:8} {title}" + (f"  -> {detail}" if detail else ""))
    print(f"\nDEPLOY {'APPROVED' if result.passed else 'BLOCKED'}")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
