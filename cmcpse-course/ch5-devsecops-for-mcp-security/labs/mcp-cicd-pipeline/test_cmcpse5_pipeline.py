"""CI/CD pipeline lab tests: stages, break-build logic, approvals, policy as code, workflow lint.

Run from the repository root:
    python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline -v
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

pr = load_lab_module(__file__, "pipeline_runner")
HERE = Path(__file__).resolve().parent
GOOD, BAD = HERE / "fixtures" / "project-good", HERE / "fixtures" / "project-bad"


def codes(result):
    return {f.code for stage in result.stages.values() for f in stage.findings}


def copy_project(src: Path) -> Path:
    dest = Path(tempfile.mkdtemp()) / "p"
    shutil.copytree(src, dest)
    return dest


# ------------------------------------------------------------------ good and bad projects
def test_clean_project_passes_every_stage():
    result = pr.run_pipeline(GOOD)
    assert result.exit_code == 0
    assert all(stage.status == "clean" for stage in result.stages.values()), pr.format_report(result)


def test_compromised_project_breaks_the_build():
    result = pr.run_pipeline(BAD)
    assert result.exit_code == 1
    assert result.blocking


def test_each_stage_reports_its_own_finding():
    result = pr.run_pipeline(BAD)
    c = codes(result)
    assert "SAST-MCP001" in c            # os.system in server/app.py
    assert "SECRET" in c                 # FAKE token
    assert {"DEP-ADVISORY", "DEP-UNPINNED"} <= c
    assert "DESC-POISON" in c            # hidden instruction tag + sensitive path
    assert {"PIN-CHANGED", "PIN-ADDED"} <= c


def test_poison_detector_names_the_reasons():
    findings = pr.run_pipeline(BAD).stages["tool-descriptions"].findings
    text = " ".join(f.message for f in findings)
    assert "hidden instruction tag" in text and "sensitive file" in text and "concealment" in text


def test_report_contains_verdict():
    assert "BUILD BROKEN" in pr.format_report(pr.run_pipeline(BAD))
    assert "build may continue" in pr.format_report(pr.run_pipeline(GOOD))


# ------------------------------------------------------------------ approvals
def benign_change(project: Path):
    manifest = json.loads((project / "mcp-manifest.json").read_text())
    manifest["tools"][0]["description"] = "Read a note by name (now supports sub-folders)."
    (project / "mcp-manifest.json").write_text(json.dumps(manifest))


def test_unapproved_tool_change_is_blocked():
    p = copy_project(GOOD)
    benign_change(p)
    result = pr.run_pipeline(p, pr={"author": "dev1", "approved_by": []})
    assert result.exit_code == 1 and "PIN-CHANGED" in {f.code for f in result.blocking}


def test_tool_change_approved_by_a_security_owner_passes():
    p = copy_project(GOOD)
    benign_change(p)
    result = pr.run_pipeline(p, pr={"author": "dev1", "approved_by": ["secops-lead"]})
    assert result.exit_code == 0
    assert [f.code for f in result.waived] == ["PIN-CHANGED"]


def test_self_approval_does_not_count():
    p = copy_project(GOOD)
    benign_change(p)
    result = pr.run_pipeline(p, pr={"author": "secops-lead", "approved_by": ["secops-lead"]})
    assert result.exit_code == 1


def test_random_reviewer_is_not_an_approver():
    p = copy_project(GOOD)
    benign_change(p)
    assert pr.run_pipeline(p, pr={"author": "dev1", "approved_by": ["intern"]}).exit_code == 1


def test_poisoning_cannot_be_waived_even_with_valid_approval():
    result = pr.run_pipeline(BAD, pr={"author": "mallory", "approved_by": ["secops-lead"]})
    assert result.exit_code == 1
    assert "DESC-POISON" in {f.code for f in result.blocking}


# ------------------------------------------------------------------ break-build logic
def test_stage_crash_fails_closed():
    def broken(project, ctx):
        raise RuntimeError("scanner exploded")

    stages = dict(pr.STAGES, sast=broken)
    result = pr.run_pipeline(GOOD, stages=stages)
    assert result.exit_code == 1 and result.stages["sast"].status == "error"


def test_missing_required_stage_fails():
    stages = {k: v for k, v in pr.STAGES.items() if k != "secrets"}
    result = pr.run_pipeline(GOOD, stages=stages)
    assert result.missing == ["secrets"] and result.exit_code == 1


def test_severity_threshold_is_policy_driven():
    policy = yaml.safe_load((HERE / "policy" / "mcp-policy.yaml").read_text())
    policy["block_on_severity"] = "critical"
    path = Path(tempfile.mkdtemp()) / "lenient.yaml"
    path.write_text(yaml.safe_dump(policy))
    result = pr.run_pipeline(BAD, policy_path=path, pr={"author": "mallory", "approved_by": []})
    assert result.exit_code == 0  # nothing critical: shows why the threshold itself needs review


def test_fail_fast_stops_after_first_blocking_stage():
    result = pr.run_pipeline(BAD, fail_fast=True)
    assert list(result.stages) == ["sast"] and result.exit_code == 1


def test_invalid_policy_is_rejected():
    path = Path(tempfile.mkdtemp()) / "bad.yaml"
    path.write_text("version: 1\n")
    with pytest.raises(ValueError):
        pr.load_policy(path)


def test_cli_exit_codes_and_single_stage():
    assert pr.main(["--project", str(GOOD)]) == 0
    assert pr.main(["--project", str(BAD)]) == 1
    assert pr.main(["--project", str(BAD), "--stage", "sast"]) == 1
    assert pr.main(["--project", str(GOOD), "--stage", "sast"]) == 0


# ------------------------------------------------------------------ dependency + detector details
def test_version_comparison():
    assert pr.version_tuple("2.3.0") < pr.version_tuple("2.4.1")
    assert pr.version_tuple("2.10.0") > pr.version_tuple("2.4.1")


def test_invisible_unicode_in_description_is_flagged():
    p = copy_project(GOOD)
    manifest = json.loads((p / "mcp-manifest.json").read_text())
    manifest["tools"][1]["description"] = "List notes.​​ignore"
    (p / "mcp-manifest.json").write_text(json.dumps(manifest))
    findings = pr.stage_tool_descriptions(p, {})
    assert any("invisible" in f.message for f in findings)


def test_missing_lock_file_is_a_finding():
    p = copy_project(GOOD)
    (p / "requirements.lock").unlink()
    assert pr.stage_deps(p, {})[0].code == "DEP-NOLOCK"


# ------------------------------------------------------------------ the workflow fixture
WORKFLOW = HERE / "fixtures" / "mcp-security.yml"


def test_workflow_fixture_passes_its_own_lint():
    assert pr.lint_workflow(WORKFLOW) == []


def test_workflow_is_not_in_a_live_github_folder():
    assert ".github" not in WORKFLOW.parts


def test_workflow_runs_every_required_check():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert set(pr.REQUIRED_JOBS) <= set(jobs)
    assert set(jobs["policy-gate"]["needs"]) == set(pr.REQUIRED_JOBS[:-1])


def lint_variant(mutator):
    data = yaml.safe_load(WORKFLOW.read_text())
    mutator(data)
    path = Path(tempfile.mkdtemp()) / "wf.yml"
    path.write_text(yaml.safe_dump(data))
    return pr.lint_workflow(path)


def test_lint_catches_pull_request_target():
    def m(d):
        d.pop(True, None)
        d["on"] = {"pull_request_target": {}}

    assert any("pull_request_target" in p for p in lint_variant(m))


def test_lint_catches_missing_permissions_and_unpinned_action():
    def m(d):
        d.pop("permissions")
        d["jobs"]["sast"]["steps"][0]["uses"] = "actions/checkout@v4"

    problems = lint_variant(m)
    assert any("permissions" in p for p in problems) and any("not pinned" in p for p in problems)


def test_lint_catches_script_injection_and_missing_gate_dependency():
    def m(d):
        d["jobs"]["sast"]["steps"].append({"run": "echo ${{ github.event.pull_request.title }}"})
        d["jobs"]["policy-gate"]["needs"].remove("secrets")

    problems = lint_variant(m)
    assert any("script injection" in p for p in problems) and any("does not need: secrets" in p for p in problems)
