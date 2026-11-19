from aisec_lab import load_lab_module

g = load_lab_module(__file__, "gitlab_model")


def ids(findings):
    return {f.id for f in findings}


def test_roles_are_ordered():
    L = g.LEVELS
    assert L["Guest"] < L["Reporter"] < L["Developer"] < L["Maintainer"] < L["Owner"]


def test_developer_reads_unprotected_secret_from_own_branch():
    p = g.misconfigured_project()
    assert p.push_ci_file("dave", "feature-x", "script: [env]")  # dev can create + push own branch
    env = p.run_pipeline_as("dave", "feature-x")
    assert env["DEPLOY_TOKEN"].startswith("FAKE-")  # leaked: the variable was not protected
    assert "SIGNING_KEY" not in env  # the protected one stays hidden on an unprotected ref


def test_developer_pushes_to_protected_branch_and_gets_protected_vars():
    p = g.misconfigured_project()
    assert p.push_ci_file("dave", "main", "script: [env]")
    env = p.run_pipeline_as("dave", "main")
    assert "SIGNING_KEY" in env  # escalation: protected variables via a pipeline on main


def test_trigger_token_usable_by_developer_on_protected_ref():
    p = g.misconfigured_project()
    assert "SIGNING_KEY" in p.trigger_pipeline("dave", 0, "main")
    assert p.trigger_pipeline("gus", 0, "main") == {}  # guests are blocked anyway


def test_job_token_open_allowlist():
    p = g.misconfigured_project()
    assert p.job_token_access("random-other-project") is True


def test_auditor_finds_all_misconfigs():
    found = ids(g.audit(g.misconfigured_project()))
    assert {"VAR-UNPROTECTED", "VAR-UNMASKED", "BRANCH-DEV-PUSH", "BRANCH-DEV-MERGE", "TRIGGER-LOW-ROLE", "JOBTOKEN-OPEN"} <= found


def test_hardening_removes_findings_and_attacks():
    p = g.misconfigured_project()
    g.harden(p)
    assert g.audit(p) == []
    assert not p.push_ci_file("dave", "main", "script: [env]")
    assert "DEPLOY_TOKEN" not in p.run_pipeline_as("dave", "feature-y")
    assert p.run_pipeline_as("dave", "feature-y").get("APP_ENV") == "staging"  # normal work still works
    assert p.trigger_pipeline("dave", 0, "main") == {}
    assert p.job_token_access("random-other-project") is False


def test_maintainer_can_still_work_after_hardening():
    p = g.misconfigured_project()
    g.harden(p)
    assert p.push_ci_file("mike", "main", "script: [make test]")
    assert "DEPLOY_TOKEN" in p.run_pipeline_as("mike", "main")


def test_unprotected_main_flagged():
    p = g.misconfigured_project()
    p.protected.clear()
    assert "BRANCH-MAIN-UNPROTECTED" in ids(g.audit(p))


def test_non_members_have_no_access():
    p = g.misconfigured_project()
    assert not p.can_push("stranger", "feature-z")
    assert p.run_pipeline_as("stranger", "main") == {}
