"""Tests for the pipeline design validator and the blue/green / canary simulators."""

import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pipeline")
SPEC = p.load(str(Path(__file__).parent / "pipeline.yaml"))


def spec():
    return copy.deepcopy(SPEC)


def rules(issues, severity="error"):
    return {i.rule for i in issues if i.severity == severity}


def test_sample_design_is_clean():
    assert p.validate(spec()) == []


def test_missing_gate_is_an_error():
    s = spec()
    s["stages"] = [x for x in s["stages"] if x["type"] != "dast"]
    assert "missing-gate" in rules(p.validate(s))


def test_every_required_gate_is_checked():
    for t in p.REQUIRED:
        s = spec()
        s["stages"] = [x for x in s["stages"] if x["type"] != t]
        assert "missing-gate" in rules(p.validate(s)), t


def test_wrong_order_sast_after_build():
    s = spec()
    st = s["stages"]
    i, j = [x["type"] for x in st].index("sast"), [x["type"] for x in st].index("build")
    st[i], st[j] = st[j], st[i]
    issues = p.validate(s)
    assert "order" in rules(issues)
    assert any("'sast' must run before 'build'" in x.message for x in issues)


def test_dast_must_come_after_staging_deploy():
    s = spec()
    st = s["stages"]
    t = [x["type"] for x in st]
    a, b = t.index("deploy-staging"), t.index("dast")
    st[a], st[b] = st[b], st[a]
    assert any("'deploy-staging' must run before 'dast'" in x.message for x in p.validate(s))


def test_allow_failure_gate_is_flagged():
    s = spec()
    next(x for x in s["stages"] if x["type"] == "sca")["allow_failure"] = True
    assert "not-blocking" in rules(p.validate(s))


def test_non_blocking_gate_is_flagged():
    s = spec()
    next(x for x in s["stages"] if x["type"] == "sast")["blocking"] = False
    assert "not-blocking" in rules(p.validate(s))


def test_missing_threshold_is_a_warning_only():
    s = spec()
    next(x for x in s["stages"] if x["type"] == "sast").pop("fail_on")
    issues = p.validate(s)
    assert "no-threshold" in rules(issues, "warning")
    assert p.errors(issues) == []


def test_missing_sign_is_a_warning():
    s = spec()
    s["stages"] = [x for x in s["stages"] if x["type"] != "sign"]
    assert "missing-sign" in rules(p.validate(s), "warning")


def test_delivery_needs_manual_approval():
    s = spec()
    next(x for x in s["stages"] if x["type"] == "deploy-prod").pop("approval")
    assert "approval" in rules(p.validate(s))
    s["mode"] = "deployment"
    assert "approval" not in rules(p.validate(s))


def test_prod_needs_rollback_health_and_strategy():
    s = spec()
    prod = next(x for x in s["stages"] if x["type"] == "deploy-prod")
    prod.pop("rollback")
    prod.pop("health_check")
    prod["strategy"] = "big-bang"
    assert {"rollback", "health-check", "strategy"} <= rules(p.validate(s))


def test_non_main_branch_warns():
    s = spec()
    s["branch"] = "develop"
    assert "branch" in rules(p.validate(s), "warning")


# ---- blue/green


def test_good_release_flips_and_keeps_old_warm():
    bg = p.BlueGreen("blue", "1.0.0")
    r = bg.release("1.1.0")
    assert r.status == "released"
    assert bg.live == "green"
    assert bg.versions == {"blue": "1.0.0", "green": "1.1.0"}


def test_unhealthy_new_env_never_gets_traffic():
    bg = p.BlueGreen("blue", "1.0.0")
    calls = []

    def health(env, ver):
        calls.append(env)
        return False

    r = bg.release("1.1.0", health=health, retries=3)
    assert r.status == "aborted"
    assert bg.live == "blue"
    assert calls == ["green"] * 3
    assert bg.versions["green"] is None


def test_health_check_retry_can_recover():
    bg = p.BlueGreen("blue", "1.0.0")
    answers = iter([False, False, True])
    r = bg.release("1.1.0", health=lambda e, v: next(answers))
    assert r.status == "released"
    assert any("health check 3/3" in e and "ok" in e for e in r.events)


def test_post_flip_failure_rolls_back():
    bg = p.BlueGreen("blue", "1.0.0")
    r = bg.release("1.1.0", post_flip=lambda v: False)
    assert r.status == "rolled-back"
    assert bg.live == "blue"
    assert any("rollback" in e for e in r.events)


def test_two_releases_alternate_colours():
    bg = p.BlueGreen("blue", "1.0.0")
    bg.release("1.1.0")
    bg.release("1.2.0")
    assert bg.live == "blue"
    assert bg.versions["blue"] == "1.2.0"


def test_manual_rollback_goes_to_previous_version():
    bg = p.BlueGreen("blue", "1.0.0")
    bg.release("1.1.0")
    assert bg.rollback() == "blue"
    assert bg.versions[bg.live] == "1.0.0"


def test_rollback_without_previous_version_fails():
    bg = p.BlueGreen("blue", "1.0.0")
    with pytest.raises(RuntimeError):
        bg.rollback()


def test_invalid_colour_rejected():
    with pytest.raises(ValueError):
        p.BlueGreen("red")


# ---- canary


def test_canary_completes_when_errors_stay_low():
    res = p.canary_rollout([5, 25, 100], lambda pct: 0.001)
    assert res["status"] == "released"
    assert [h[0] for h in res["history"]] == [5, 25, 100]


def test_canary_stops_at_first_bad_step():
    res = p.canary_rollout([5, 25, 50, 100], lambda pct: 0.05 if pct >= 25 else 0.0)
    assert res["status"] == "rolled-back"
    assert res["stopped_at"] == 25
    assert [h[0] for h in res["history"]] == [5, 25]
