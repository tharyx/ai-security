"""Deployment approval tests: a protected environment plus a proper approval passes;
each way of faking or skipping the approval blocks the deploy.

Run from the repository root:
    python -m pytest 06-ai-devsecops/cicd -v
"""

import copy
from datetime import datetime, timezone
from pathlib import Path

from aisec_lab import load_lab_module

da = load_lab_module(__file__, "deploy_approval")
FIX = Path(__file__).parent / "fixtures"
GOOD_ENV = da.load_json(FIX / "env-production.good.json")
BAD_ENV = da.load_json(FIX / "env-production.bad.json")
GOOD_APPROVAL = da.load_json(FIX / "approval.good.json")
BAD_APPROVAL = da.load_json(FIX / "approval.bad.json")
GATE = da.load_json(FIX / "gate-result.good.json")
DIGEST = GATE["image_digest"]
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def check(env=GOOD_ENV, approval=GOOD_APPROVAL, gate=GATE, digest=DIGEST, **kw):
    return da.evaluate(env, approval, gate, digest, now=NOW, **kw)


def changed(base: dict, **updates) -> dict:
    out = copy.deepcopy(base)
    out.update(updates)
    return out


def test_good_environment_and_approval_pass():
    result = check()
    assert result.passed, result.failures


def test_unprotected_environment_fails_every_env_rule():
    assert {"ENV-001", "ENV-002", "ENV-003", "ENV-004", "ENV-005"} <= set(check(env=BAD_ENV).failures)


def test_self_approval_is_blocked():
    fails = check(approval=changed(GOOD_APPROVAL, approved_by="lee.dev")).failures
    assert "APR-002" in fails


def test_commit_author_cannot_approve_even_if_someone_else_started_the_run():
    approval = changed(GOOD_APPROVAL, triggered_by="release-bot", commit_authors=["priya.sec"])
    assert "APR-002" in check(approval=approval).failures


def test_approver_outside_the_group_is_blocked():
    assert "APR-003" in check(approval=changed(GOOD_APPROVAL, approved_by="random.contractor")).failures


def test_approval_for_a_different_digest_is_blocked():
    """The classic swap: approve the reviewed image, deploy another one."""
    other = "sha256:" + "0" * 64
    assert "APR-004" in check(digest=other).failures
    assert "APR-004" in check(approval=changed(GOOD_APPROVAL, digest=other)).failures


def test_approval_before_the_gate_ran_is_blocked():
    approval = changed(GOOD_APPROVAL, approved_at="2026-11-18T09:00:00Z")   # gate ran at 09:10
    assert "APR-005" in check(approval=approval).failures


def test_failed_gate_cannot_be_approved_around():
    assert "APR-005" in check(gate=changed(GATE, decision="BLOCKED")).failures


def test_stale_approval_is_blocked():
    approval = changed(GOOD_APPROVAL, approved_at="2026-11-15T09:40:00Z")
    gate = changed(GATE, generated_at="2026-11-15T09:10:00Z")
    assert set(check(approval=approval, gate=gate).failures) == {"APR-006"}


def test_missing_evidence_fails_closed():
    fails = check(approval=None, gate=None).failures
    assert {"APR-001", "APR-002", "APR-004", "APR-005", "APR-006"} <= set(fails)


def test_bad_fixture_shows_the_real_world_combination():
    assert {"APR-002", "APR-003", "APR-004", "APR-005"} <= set(check(approval=BAD_APPROVAL).failures)


def test_cli_exit_codes():
    args = ["--environment", str(FIX / "env-production.good.json"), "--gate", str(FIX / "gate-result.good.json"),
            "--deploy-digest", DIGEST, "--now", "2026-11-18T12:00:00Z"]
    assert da.main(args + ["--approval", str(FIX / "approval.good.json")]) == 0
    assert da.main(args + ["--approval", str(FIX / "approval.bad.json")]) == 1
