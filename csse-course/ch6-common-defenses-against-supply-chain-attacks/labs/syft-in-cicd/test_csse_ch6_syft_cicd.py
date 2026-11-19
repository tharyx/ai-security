"""Tests for the SBOM-in-CI runner."""

import json

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pipeline_runner")


def test_main_branch_produces_and_archives_sbom():
    r = p.run(p.PIPELINE, p.WORKSPACE, {"CI_COMMIT_BRANCH": "main"})
    assert r["jobs"] == {"build": "success", "sbom": "success", "gate": "success"}
    doc = json.loads(r["artifacts"]["sbom.cdx.json"])
    assert doc["bomFormat"] == "CycloneDX" and len(doc["components"]) == 3


def test_feature_branch_skips_sbom_job_and_gate_fails_without_it():
    r = p.run(p.PIPELINE, p.WORKSPACE, {"CI_COMMIT_BRANCH": "feature-x"})
    assert r["jobs"]["sbom"] == "skipped" and r["jobs"]["gate"] == "failed"
    assert r["artifacts"] == {}


def test_tag_pipeline_runs_sbom():
    r = p.run(p.PIPELINE, p.WORKSPACE, {"CI_COMMIT_TAG": "v1.0.0"})
    assert r["jobs"]["sbom"] == "success"


def test_empty_requirements_fails_the_gate():
    r = p.run(p.PIPELINE, {"requirements.txt": ""}, {"CI_COMMIT_BRANCH": "main"})
    assert r["jobs"]["gate"] == "failed"


def test_unknown_command_fails_job_and_stops():
    y = "stages: [a, b]\njob1:\n  stage: a\n  script: ['rm -rf /']\njob2:\n  stage: b\n  script: ['echo hi']\n"
    r = p.run(y, {})
    assert r["jobs"] == {"job1": "failed"} and any("unknown command" in l for l in r["log"])


def test_workspace_not_mutated():
    ws = dict(p.WORKSPACE)
    p.run(p.PIPELINE, ws, {"CI_COMMIT_BRANCH": "main"})
    assert ws == p.WORKSPACE


def test_rule_evaluator():
    assert p._eval_rule('$A == "x" || $B', {"A": "x"})
    assert p._eval_rule('$A == "x" || $B', {"B": "1"})
    assert not p._eval_rule('$A == "x"', {"A": "y"})


def test_lint_good_pipeline_is_clean():
    assert p.lint_pipeline(p.PIPELINE) == []


def test_lint_flags_unpinned_tool_and_missing_retention():
    bad = p.PIPELINE.replace("1.0.0", "latest").replace("    expire_in: 90 days\n", "")
    msgs = " ".join(p.lint_pipeline(bad))
    assert "not pinned" in msgs and "expire_in" in msgs


def test_lint_no_sbom_job():
    assert p.lint_pipeline("stages: [a]\nj:\n  stage: a\n  script: ['echo']\n") == ["no job generates an SBOM"]
