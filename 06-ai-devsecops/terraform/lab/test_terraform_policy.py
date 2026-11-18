"""Policy-as-code tests: every rule fires on the vulnerable plan, the secure plan is clean,
and each test that changes one setting proves the specific exposure is caught.

Run from the repository root:
    python -m pytest 06-ai-devsecops/terraform -v
"""

import copy
from datetime import date
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

pc = load_lab_module(__file__, "policy_check")
LAB = Path(__file__).parent
VULN = pc.load_plan(LAB / "plans" / "vulnerable.plan.json")
SECURE = pc.load_plan(LAB / "plans" / "secure.plan.json")
WAIVERS = pc.load_waivers(LAB / "waivers.json")
TODAY = date(2026, 11, 18)


def change(plan: dict, address: str) -> dict:
    return next(rc["change"] for rc in plan["resource_changes"] if rc["address"] == address)


def ids(plan: dict, **kw) -> set[str]:
    return pc.check_plan(plan, today=TODAY, **kw).rule_ids()


# ---------- Part 1: the vulnerable plan is caught --------------------------------

def test_vulnerable_plan_triggers_every_rule():
    assert ids(VULN) == set(pc.RULES)


def test_vulnerable_plan_fails_the_pipeline():
    assert pc.check_plan(VULN, today=TODAY).failed("HIGH")
    assert pc.main([str(LAB / "plans" / "vulnerable.plan.json")]) == 1


def test_internet_exposed_ray_ports_are_named_in_the_finding():
    msgs = [f.message for f in pc.check_plan(VULN, today=TODAY).findings if f.rule_id == "TF-AI-030"]
    assert any("8265" in m for m in msgs)  # the Ray Jobs API port abused in ShadowRay-style attacks


# ---------- Part 2: the secure plan holds ----------------------------------------

def test_secure_plan_has_only_the_org_trail_finding():
    assert ids(SECURE) == {"TF-AI-060"}


def test_secure_plan_passes_with_its_approved_waiver():
    report = pc.check_plan(SECURE, waivers=WAIVERS, today=TODAY)
    assert report.findings == []
    assert not report.failed("LOW")
    assert [f.rule_id for f, _ in report.waived] == ["TF-AI-060"]


def test_secure_plan_cli_passes_at_the_default_threshold():
    # The only open finding without a waiver is MEDIUM, below the default fail-on=HIGH.
    assert pc.main([str(LAB / "plans" / "secure.plan.json")]) == 0


# ---------- Part 3: one small change -> the right rule catches it ------------------

def test_making_the_vector_db_public_is_critical():
    plan = copy.deepcopy(SECURE)
    change(plan, "aws_opensearch_domain.vectors")["after"]["vpc_options"] = []
    report = pc.check_plan(plan, today=TODAY)
    assert any(f.rule_id == "TF-AI-020" and f.severity == "CRITICAL" for f in report.findings)


def test_one_relaxed_public_access_flag_is_enough_to_fail():
    plan = copy.deepcopy(SECURE)
    change(plan, "aws_s3_bucket_public_access_block.model_artifacts")["after"]["restrict_public_buckets"] = False
    hits = [f.address for f in pc.check_plan(plan, today=TODAY).findings if f.rule_id == "TF-AI-001"]
    assert hits == ["aws_s3_bucket.model_artifacts"]  # only the bucket that changed


def test_aws_managed_kms_key_is_not_cmek():
    # sse_algorithm "aws:kms" with no key id uses the AWS-managed key: you don't control its policy.
    plan = copy.deepcopy(SECURE)
    change(plan, "aws_s3_bucket_server_side_encryption_configuration.training_data")["after_unknown"]["rule"] = [{}]
    hits = [f.address for f in pc.check_plan(plan, today=TODAY).findings if f.rule_id == "TF-AI-003"]
    assert hits == ["aws_s3_bucket.training_data"]


def test_oidc_trust_with_wildcard_subject_is_rejected():
    plan = copy.deepcopy(SECURE)
    after = change(plan, "aws_iam_role.ci_oidc")["after"]
    after["assume_role_policy"] = after["assume_role_policy"].replace(
        "repo:acme/support-llm:environment:production", "repo:*")
    assert "TF-AI-042" in ids(plan)


def test_policy_reads_the_final_value_not_the_hcl():
    # In HCL the policy is jsonencode({...}); in the plan it is the final JSON string.
    plan = copy.deepcopy(SECURE)
    after = change(plan, "aws_iam_role_policy.sagemaker_exec")["after"]
    after["policy"] = after["policy"].replace('"s3:GetObject"', '"s3:*"').replace(
        "arn:aws:s3:::acme-llm-model-artifacts/support-llm/*", "*")
    assert "TF-AI-040" in ids(plan)


def test_literal_bucket_name_links_companion_resources_too():
    plan = copy.deepcopy(VULN)
    plan["resource_changes"].append({
        "address": "aws_s3_bucket_versioning.training_data", "mode": "managed",
        "type": "aws_s3_bucket_versioning", "name": "training_data",
        "change": {"actions": ["create"], "after": {"bucket": "acme-llm-training-data",
                                                    "versioning_configuration": [{"status": "Enabled"}]}},
    })
    hits = [f.address for f in pc.check_plan(plan, today=TODAY).findings if f.rule_id == "TF-AI-004"]
    assert hits == ["aws_s3_bucket.model_artifacts"]


def test_resources_being_deleted_are_ignored():
    plan = copy.deepcopy(VULN)
    change(plan, "aws_iam_access_key.ci_deployer")["actions"] = ["delete"]
    assert "TF-AI-041" not in ids(plan)


# ---------- Part 4: the exception process is a control too ----------------------------

def test_expired_waiver_stops_working():
    report = pc.check_plan(SECURE, waivers=WAIVERS, today=date(2027, 6, 1))
    assert report.rule_ids() == {"TF-AI-060"}
    assert report.expired_waivers and report.failed("MEDIUM")


def test_waiver_is_scoped_to_one_rule():
    report = pc.check_plan(VULN, waivers=WAIVERS, today=TODAY)
    assert "TF-AI-020" in report.rule_ids()  # the org-trail waiver must not hide anything else


@pytest.mark.parametrize("rule_id", ["TF-AI-030", "TF-AI-020"])
def test_disabling_a_rule_is_visible_and_only_hides_that_rule(rule_id):
    found = ids(VULN, disabled={rule_id})
    assert rule_id not in found
    assert found == set(pc.RULES) - {rule_id}
