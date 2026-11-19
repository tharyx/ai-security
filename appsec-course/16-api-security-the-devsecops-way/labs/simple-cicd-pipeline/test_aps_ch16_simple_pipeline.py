import copy
from pathlib import Path

import pytest
from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pipeline")
DEFN = p.load(Path(__file__).resolve().parent / "fixtures" / "pipeline.json")


def test_stages_run_in_order_and_manual_deploy_waits_for_approval():
    r = p.run(DEFN, branch="main")
    assert [j.status for j in r.jobs.values()][:4] == ["success", "success", "failed (allowed)", "success"]
    assert r.jobs["deploy-prod"].status == "manual" and r.status == "blocked (manual)"


def test_approved_deploy_runs_and_pipeline_passes():
    r = p.run(DEFN, branch="main", approvals={"deploy-prod"})
    assert r.jobs["deploy-prod"].status == "success" and r.status == "passed"


def test_failed_test_blocks_later_stages():
    r = p.run(DEFN, branch="main", approvals={"deploy-prod"}, extra_vars={"SIMULATE_TEST_FAILURE": "1"})
    assert r.jobs["unit-tests"].status == "failed"
    assert r.jobs["package"].status == "skipped" and r.jobs["deploy-prod"].status == "skipped"
    assert r.status == "failed"


def test_allow_failure_job_does_not_block():
    r = p.run(DEFN, branch="main")
    assert r.jobs["lint"].status == "failed (allowed)" and r.jobs["package"].status == "success"


def test_artifacts_flow_only_along_needs_and_have_digests():
    r = p.run(DEFN, branch="main")
    assert len(r.jobs["build"].artifacts["dist/orders-api.tar"]) == 64
    d = copy.deepcopy(DEFN)
    d["jobs"]["package"]["needs"] = ["unit-tests"]  # forgot to need the build job
    r2 = p.run(d, branch="main")
    assert r2.jobs["package"].status == "failed" and "artifact missing" in r2.jobs["package"].log[0]


def test_masked_secret_never_appears_in_logs():
    r = p.run(DEFN, branch="main", approvals={"deploy-prod"})
    log = " ".join(r.jobs["deploy-prod"].log)
    assert "FAKE-deploy-token-lab-only" not in log and "[MASKED]" in log


def test_protected_variable_and_deploy_job_not_available_on_feature_branch():
    r = p.run(DEFN, branch="feature/x", approvals={"deploy-prod"})
    assert r.jobs["deploy-prod"].status == "not-run (rules)"
    d = copy.deepcopy(DEFN)
    d["jobs"]["deploy-prod"].pop("only_branches")  # someone removes the branch rule
    r2 = p.run(d, branch="feature/x", approvals={"deploy-prod"})
    assert r2.jobs["deploy-prod"].status == "failed" and "not available" in r2.jobs["deploy-prod"].log[0]


def test_invalid_definitions_are_rejected():
    bad = {"stages": ["build", "deploy"], "jobs": {
        "deploy": {"stage": "deploy", "script": ["deploy"], "needs": ["build"]},
        "build": {"stage": "build", "script": ["compile", "curl-bash"], "needs": ["deploy"]}}}
    errs = " ".join(p.validate(bad))
    assert "later stage" in errs and "cycle" in errs and "curl-bash" in errs
    with pytest.raises(p.PipelineError):
        p.run(bad)
