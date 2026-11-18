"""GitHub Actions linter tests.

Run from the repository root:
    python -m pytest 06-ai-devsecops/cicd -v
"""

import copy
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

wl = load_lab_module(__file__, "workflow_lint")
LAB = Path(__file__).parent
SHA = "@" + "a" * 40


def lint_ids(wf) -> set[str]:
    return {f.rule_id for f in wl.lint(wf)}


def from_yaml(text: str, release: bool = False):
    return wl.Workflow("test.yml", yaml.safe_load(text), release)


def secure_release():
    return copy.deepcopy(wl.load(LAB / "secure" / "release.yml", release=True))


# ---------- Part 1 and 2: vulnerable vs secure -------------------------------------------

def test_vulnerable_workflows_trigger_every_rule():
    found = lint_ids(wl.load(LAB / "vulnerable" / "release.yml", release=True))
    found |= lint_ids(wl.load(LAB / "vulnerable" / "pr-eval-bot.yml"))
    assert found == set(wl.RULES)


def test_secure_workflows_are_clean():
    assert wl.lint(wl.load(LAB / "secure" / "release.yml", release=True)) == []
    assert wl.lint(wl.load(LAB / "secure" / "pr-eval-bot.yml")) == []


def test_cli_exit_codes():
    assert wl.main([str(LAB / "vulnerable" / "pr-eval-bot.yml")]) == 1
    assert wl.main(["--release", str(LAB / "secure" / "release.yml"), str(LAB / "secure" / "pr-eval-bot.yml")]) == 0


# ---------- Part 3: the attacks behind each rule -------------------------------------------

def test_yaml_on_key_becomes_true_and_is_handled():
    wf = wl.load(LAB / "secure" / "pr-eval-bot.yml")
    assert True in wf.data and "on" not in wf.data   # the YAML 1.1 gotcha
    assert wf.triggers() == {"pull_request"}


def test_pull_request_target_is_ok_if_it_never_runs_pr_code():
    # e.g. a labeler that only reads metadata through the API
    wf = from_yaml(f"on: pull_request_target\npermissions: {{contents: read, pull-requests: write}}\n"
                   f"jobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n"
                   f"      - uses: actions/labeler{SHA}\n")
    assert "GHA-003" not in lint_ids(wf)


def test_pwn_request_is_critical():
    wf = from_yaml(f"on: pull_request_target\npermissions: {{contents: read}}\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                   f"    steps:\n      - uses: actions/checkout{SHA}\n        with:\n"
                   "          ref: refs/pull/${{ github.event.number }}/merge\n          persist-credentials: false\n")
    assert [f.severity for f in wl.lint(wf) if f.rule_id == "GHA-003"] == ["CRITICAL"]


@pytest.mark.parametrize("expr, bad", [
    ("${{ github.event.pull_request.title }}", True),
    ("${{ github.event.issue.body }}", True),
    ("${{ github.event.comment.body }}", True),
    ("${{ github.head_ref }}", True),
    ("${{ github.event.pull_request.head.ref }}", True),
    ("${{ github.sha }}", False),
    ("${{ steps.build.outputs.digest }}", False),
])
def test_script_injection_contexts(expr, bad):
    wf = from_yaml(f"on: push\npermissions: {{contents: read}}\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                   f"    steps:\n      - run: echo \"{expr}\"\n")
    assert ("GHA-004" in lint_ids(wf)) is bad


def test_untrusted_value_through_env_is_safe():
    wf = wl.load(LAB / "secure" / "pr-eval-bot.yml")
    assert "github.event.pull_request.title" in str(wf.data)  # it IS used ...
    assert "GHA-004" not in lint_ids(wf)                       # ... but only through env:


@pytest.mark.parametrize("uses, ok", [
    ("actions/checkout@v4", False),
    ("actions/checkout@main", False),
    ("actions/checkout@" + "b" * 40, True),
    ("./.github/actions/local", True),
    ("docker://alpine@sha256:" + "c" * 64, True),
])
def test_action_pinning(uses, ok):
    wf = from_yaml(f"on: push\npermissions: {{contents: read}}\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                   f"    steps:\n      - uses: {uses}\n        with: {{persist-credentials: false}}\n")
    assert ("GHA-001" not in lint_ids(wf)) is ok


def test_or_true_turns_a_gate_into_a_suggestion():
    wf = secure_release()
    step = next(s for s in wf.data["jobs"]["verify"]["steps"] if s.get("name") == "Dependency audit")
    step["run"] += " || true"
    assert "GHA-006" in lint_ids(wf)


def test_workflow_level_write_permission_is_flagged():
    wf = secure_release()
    wf.data["permissions"] = {"contents": "write"}
    assert "GHA-002" in lint_ids(wf)


def test_long_lived_keys_in_env_are_flagged():
    wf = secure_release()
    wf.data["jobs"]["deploy"]["steps"][-1]["env"] = {"AWS_SECRET_ACCESS_KEY": "${{ secrets.AWS_SECRET_ACCESS_KEY }}"}
    assert "GHA-005" in lint_ids(wf)


def test_removing_the_environment_removes_the_human_gate():
    wf = secure_release()
    del wf.data["jobs"]["deploy"]["environment"]
    assert "GHA-010" in lint_ids(wf)


def test_removing_signing_is_caught_in_release_mode_only():
    wf = secure_release()
    for job in wf.data["jobs"].values():
        job["steps"] = [s for s in job["steps"] if "cosign" not in str(s) and "attest" not in str(s)]
    msgs = [f.message for f in wl.lint(wf) if f.rule_id == "GHA-009"]
    assert msgs == ["no signing / provenance stage"]
    wf.release = False
    assert "GHA-009" not in lint_ids(wf)
