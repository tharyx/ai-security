"""Tests for continuous assessment: drift detection, posture trend, exceptions, cadence.

Run from the repository root:
    python -m pytest 09-enterprise-architecture -v
"""

import copy
from datetime import date, datetime

import pytest
import yaml

from aisec_lab import load_lab_module

posture = load_lab_module(__file__, "posture")
reviewer = load_lab_module(__file__, "reviewer")
MATRIX = reviewer.load_matrix()


def raw(name: str) -> dict:
    return yaml.safe_load((reviewer.ARCH_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def kinds(drifts, kind):
    return {d.target for d in drifts if d.kind == kind}


# ---------- drift: declared vs observed -------------------------------------------

def test_no_drift_when_the_system_matches_the_design():
    assert posture.diff_architecture(raw("secure_aws"), raw("secure_aws")) == []


def test_drifted_design_reports_the_security_relevant_changes_with_their_controls():
    drifts = posture.diff_architecture(raw("secure_gcp"), raw("drifted_gcp"))
    by_target = {d.target: d for d in drifts}
    assert by_target["agent.egress"].control == "NET-03"
    assert by_target["ai-gateway.guardrails.input"].control == "GR-01"
    assert by_target["internet->model"].control == "NET-04"
    assert kinds(drifts, "new_exception") == {"GR-01", "NET-03", "NET-04"}


def test_descriptive_service_text_is_not_reported_as_drift():
    drifts = posture.diff_architecture(raw("secure_gcp"), raw("drifted_gcp"))
    assert not any(d.target.endswith(".service") for d in drifts)


def test_a_shadow_ai_component_is_found():
    observed = copy.deepcopy(raw("secure_azure"))
    observed["components"].append({"id": "team-notebook", "type": "frontend", "zone": "public"})
    drifts = posture.diff_architecture(raw("secure_azure"), observed)
    assert kinds(drifts, "added_component") == {"team-notebook"}


def test_a_new_identity_without_owner_points_to_iam_05():
    observed = copy.deepcopy(raw("secure_aws"))
    observed["identities"].append({"id": "role-hackday-agent", "credential": "short_lived"})
    d = next(d for d in posture.diff_architecture(raw("secure_aws"), observed) if d.kind == "added_identity")
    assert d.target == "role-hackday-agent" and d.control == "IAM-05"


def test_a_widened_permission_is_drift_on_iam_02():
    observed = copy.deepcopy(raw("secure_aws"))
    observed["identities"][0]["permissions"].append("bedrock:*")
    d = next(d for d in posture.diff_architecture(raw("secure_aws"), observed) if d.kind == "changed_identity")
    assert d.control == "IAM-02"


# ---------- posture trend over scheduled runs -------------------------------------

def run_on(name, when):
    return posture.summarize(when, reviewer.review(reviewer.parse_architecture(raw(name)), MATRIX, today=when))


def test_posture_trend_shows_regressions_between_runs():
    jan = run_on("secure_gcp", date(2026, 1, 5))
    jun = run_on("drifted_gcp", date(2026, 6, 1))
    oct_ = run_on("drifted_gcp", date(2026, 10, 1))
    assert jan.score == 100
    assert posture.regressions(jan, jun) == ["NET-03", "NET-04"]
    assert posture.regressions(jun, oct_) == ["GR-01"]  # the accepted exception expired
    assert oct_.score < jun.score < jan.score


def test_accepted_findings_do_not_lower_the_score_but_are_tracked():
    jun = run_on("drifted_gcp", date(2026, 6, 1))
    assert jun.accepted == {"GR-01"} and "GR-01" not in jun.failed


# ---------- exceptions and cadence ------------------------------------------------

def test_exception_alerts_warn_before_expiry_and_flag_expired():
    alerts = posture.exception_alerts(raw("drifted_gcp")["exceptions"], date(2026, 9, 10))
    assert ("GR-01", "expiring", 20) in alerts
    assert any(c == "NET-03" and s == "expired" for c, s, _ in alerts)
    assert not any(c == "NET-04" for c, _, _ in alerts)  # far in the future


def test_overdue_lists_missing_and_late_assessments():
    last = {"redteam_suite": date(2026, 5, 29), "architecture_review": date(2026, 3, 2)}
    assert posture.overdue(last, date(2026, 6, 1)) == ["access_review", "architecture_review", "manual_red_team"]


def test_attack_surface_minutes():
    assert posture.attack_surface_minutes(datetime(2026, 5, 4, 9, 0), datetime(2026, 5, 4, 10, 30)) == 90
    with pytest.raises(ValueError):
        posture.attack_surface_minutes(datetime(2026, 5, 4, 10, 0), datetime(2026, 5, 4, 9, 0))


def test_assess_demo_runs():
    import subprocess
    import sys

    out = subprocess.run([sys.executable, "assess.py"], cwd=reviewer.HERE, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "internet->model" in out.stdout and "new failures: GR-01" in out.stdout
