from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "schedules")
FIX = Path(__file__).parent / "fixtures"
T = "http://staging.example.test"


@pytest.mark.parametrize("profile", s.PROFILES)
def test_generated_plans_validate(profile):
    assert s.validate_plan(s.generate_plan(profile, T, openapi_url=T + "/openapi.json")) == []


def test_commit_is_passive_only_and_short():
    types = [j["type"] for j in s.generate_plan("commit", T)["jobs"]]
    assert "activeScan" not in types and types[-1] == "report"


def test_weekly_has_active_scan_with_time_budget():
    jobs = s.generate_plan("weekly", T)["jobs"]
    active = next(j for j in jobs if j["type"] == "activeScan")
    assert active["parameters"]["maxScanDurationInMins"] > 0


def test_monthly_is_authenticated_without_literal_password():
    plan = s.generate_plan("monthly", T)
    ctx = plan["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "json"
    assert ctx["users"][0]["credentials"]["password"].startswith("${")
    assert '"password":"{%password%}"' in ctx["authentication"]["parameters"]["loginRequestBody"]


def test_yaml_roundtrips_and_hides_meta():
    text = s.to_yaml(s.generate_plan("weekly", T))
    data = yaml.safe_load(text)
    assert set(data) == {"env", "jobs"}


def test_validator_catches_bad_plans():
    plan = s.generate_plan("commit", "http://prod.example.com")
    plan["jobs"].insert(1, {"type": "activeScan", "parameters": {"context": "app"}})
    plan["jobs"].append({"type": "nonsense"})
    errs = " | ".join(s.validate_plan(plan))
    assert "allowed target" in errs
    assert "must not run an active scan" in errs
    assert "unknown job type" in errs
    assert "report job must be last" in errs
    assert "maxScanDurationInMins" in errs


def test_validator_flags_literal_password_and_unknown_user():
    plan = s.generate_plan("monthly", T)
    plan["env"]["contexts"][0]["users"][0]["credentials"]["password"] = "hunter2-fake"
    plan["jobs"][2]["parameters"]["user"] = "ghost"
    errs = " | ".join(s.validate_plan(plan))
    assert "literal password" in errs and "ghost" in errs


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        s.generate_plan("daily", T)


def test_parse_report_fixture():
    alerts = s.parse_zap_report((FIX / "weekly_report.json").read_text())
    by_id = {a.plugin_id: a for a in alerts}
    assert by_id["40012"].risk == "High" and by_id["10021"].count == 2
    assert len(alerts) == 7


def test_gate_commit_passes_weekly_fails():
    commit = s.parse_zap_report((FIX / "commit_report.json").read_text())
    weekly = s.parse_zap_report((FIX / "weekly_report.json").read_text())
    assert s.evaluate_gate(commit, s.POLICIES["commit"])[0] is True
    ok, why = s.evaluate_gate(weekly, s.POLICIES["weekly"])
    assert not ok and any("SQL Injection" in r for r in why)


def test_monthly_policy_fails_on_medium():
    commit = s.parse_zap_report((FIX / "commit_report.json").read_text())
    assert s.evaluate_gate(commit, s.POLICIES["monthly"])[0] is False  # CSP header Medium


def test_baseline_and_accepted_risk_suppress_known_debt():
    weekly = s.parse_zap_report((FIX / "weekly_report.json").read_text())
    pol = s.GatePolicy(fail_on="High", baseline={"40012"}, accepted={"40018"})
    assert s.evaluate_gate(weekly, pol)[0] is True
