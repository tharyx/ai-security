"""Tests for the simulated build -> SCA -> SAST -> DAST -> deploy runner."""

import copy

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "runner")
PIPE = r.load_pipeline()
ADV = r.load_advisories()


def fixed_app():
    app = r.load_app()
    app["package.json"] = app["package.json"].replace("4.17.15", "4.17.21")
    return app


def run(app=None, pipe=None, branch="main"):
    return r.run_pipeline(pipe or copy.deepcopy(PIPE), app or r.load_app(), ADV, branch)


def test_stages_are_in_the_expected_order():
    assert PIPE["stages"] == ["build", "sca", "sast", "dast", "deploy"]


def test_vulnerable_dependency_breaks_the_build_at_sca():
    res = run()
    assert res.status == "failed"
    assert res.job("build").status == "success"
    assert res.job("dependency-scan").status == "failed"
    f = res.job("dependency-scan").findings[0]
    assert f["rule"] == "ADV-DEMO-001" and f["severity"] == "high"


def test_later_stages_are_skipped_after_failure():
    res = run()
    for name in ("code-scan", "baseline-scan", "deploy-staging"):
        assert res.job(name).status == "skipped"
    assert "deployed" not in res.workspace


def test_fixed_commit_reaches_deploy():
    res = run(fixed_app())
    assert res.status == "success"
    assert res.order == ["build", "dependency-scan", "code-scan", "baseline-scan", "deploy-staging"]
    assert res.workspace["deployed"] == "webshop-1.0.0"


def test_medium_and_low_findings_are_reported_but_do_not_break():
    res = run(fixed_app())
    sast = {f["rule"] for f in res.job("code-scan").findings}
    dast = {f["rule"] for f in res.job("baseline-scan").findings}
    assert sast == {"js-weak-random"}
    assert dast == {"missing-csp", "server-banner"}
    assert res.job("code-scan").status == "success"


def test_sql_concatenation_in_new_code_breaks_sast():
    app = fixed_app()
    app["server.js"] += '\nconst q = "SELECT * FROM users WHERE id = " + req.query.id;\n'
    res = run(app)
    assert res.job("code-scan").status == "failed"
    assert res.job("baseline-scan").status == "skipped"
    hit = [f for f in res.job("code-scan").findings if f["rule"] == "js-sql-concat"][0]
    assert hit["where"].startswith("server.js:")


def test_exposed_git_folder_breaks_dast():
    import json
    app = fixed_app()
    rt = json.loads(app["runtime.json"])
    rt["paths_exposed"].append("/.git/config")
    app["runtime.json"] = json.dumps(rt)
    res = run(app)
    assert res.job("baseline-scan").status == "failed"
    assert res.job("deploy-staging").status == "skipped"


def test_cookie_without_httponly_is_medium_finding():
    import json
    app = fixed_app()
    rt = json.loads(app["runtime.json"])
    rt["cookies"][0]["httponly"] = False
    app["runtime.json"] = json.dumps(rt)
    res = run(app)
    assert "cookie-httponly" in {f["rule"] for f in res.job("baseline-scan").findings}
    assert res.status == "success"  # medium is below the high threshold


def test_lowering_threshold_to_medium_blocks_on_csp():
    pipe = copy.deepcopy(PIPE)
    pipe["jobs"]["baseline-scan"]["fail_on"] = "medium"
    res = run(fixed_app(), pipe)
    assert res.job("baseline-scan").status == "failed"


def test_allow_failure_does_not_stop_the_pipeline():
    pipe = copy.deepcopy(PIPE)
    pipe["jobs"]["dependency-scan"]["allow_failure"] = True
    res = run(pipe=pipe)
    assert res.job("dependency-scan").status == "failed_allowed"
    assert res.status == "success"
    assert res.job("deploy-staging").status == "success"


def test_deploy_only_runs_on_main():
    res = run(fixed_app(), branch="feature-x")
    assert res.status == "success"
    assert res.job("deploy-staging").status == "excluded"
    assert "deployed" not in res.workspace


def test_dast_needs_the_build_artifact():
    pipe = copy.deepcopy(PIPE)
    del pipe["jobs"]["build"]
    res = run(fixed_app(), pipe)
    assert res.job("baseline-scan").status == "failed"
    assert "build" in res.job("baseline-scan").reason


def test_fixed_version_boundary_is_exclusive():
    app = r.load_app()
    app["package.json"] = app["package.json"].replace("4.17.15", "4.17.20")
    assert run(app).job("dependency-scan").status == "failed"
    app["package.json"] = app["package.json"].replace("4.17.20", "4.17.21")
    assert run(app).job("dependency-scan").status == "success"


def test_unknown_tool_in_pipeline_raises():
    pipe = copy.deepcopy(PIPE)
    pipe["jobs"]["build"]["tool"] = "nope"
    with pytest.raises(KeyError):
        run(pipe=pipe)
