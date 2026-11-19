from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

rr = load_lab_module(__file__, "risk_register")
FIX = Path(__file__).resolve().parent / "fixtures"
TODAY = date(2026, 11, 19)
WEAK = rr.load(FIX / "register_spreadsheet.json")
GOOD = rr.load(FIX / "register_governed.json")


def by_id(risks, rid):
    return next(r for r in risks if r.id == rid)


def test_spreadsheet_register_fails_gate_and_governed_register_passes():
    assert rr.gate(WEAK, today=TODAY) == 1
    assert rr.gate(GOOD, today=TODAY) == 0


def test_silent_acceptance_of_critical_risk_by_team_lead_is_caught():
    issues = rr.validate(by_id(WEAK, "R-01"), today=TODAY)
    assert {"ACCEPTED_WITHOUT_AUTHORITY", "ACCEPT_WITHOUT_REASON", "ACCEPT_WITHOUT_REVIEW_DATE"} <= set(issues)
    assert rr.band(by_id(WEAK, "R-01").residual) == "CRITICAL"


def test_mitigate_needs_real_controls():
    assert "MITIGATE_WITHOUT_CONTROL" in rr.validate(by_id(WEAK, "R-02"), today=TODAY)
    r03 = rr.validate(by_id(WEAK, "R-03"), today=TODAY)
    assert {"CONTROL_WITH_NO_EFFECT", "NO_OWNER", "RESIDUAL_ABOVE_APPETITE"} <= set(r03)


def test_transfer_cannot_remove_more_than_one_impact_level():
    weak = rr.validate(by_id(WEAK, "R-04"), today=TODAY)
    assert {"TRANSFER_WITHOUT_PARTY", "TRANSFER_OVERCLAIMED", "NO_CONTINUITY_PLAN"} <= set(weak)
    good = by_id(GOOD, "R-04")
    assert good.residual_li() == (2, 4)  # impact 5 -> 4, never lower via transfer


def test_avoid_drops_residual_to_zero_only_with_a_described_change():
    assert by_id(GOOD, "R-05").residual == 0
    assert by_id(WEAK, "R-05").residual == 12
    assert "AVOID_WITHOUT_CHANGE" in rr.validate(by_id(WEAK, "R-05"), today=TODAY)


def test_mitigation_math_inherent_vs_residual():
    r = by_id(GOOD, "R-01")
    assert r.inherent == 20 and r.residual == 3
    assert rr.band(r.inherent) == "CRITICAL" and rr.band(r.residual) == "LOW"


def test_acceptance_expires_when_review_date_passes():
    r = by_id(GOOD, "R-06")
    assert rr.validate(r, today=TODAY) == []
    assert "ACCEPTANCE_EXPIRED" in rr.validate(r, today=date(2027, 4, 1))


def test_identification_coverage_gap_is_reported():
    assert rr.coverage_gaps(WEAK) == ["threat-landscape"]
    assert rr.coverage_gaps(GOOD) == []


def test_suggest_treatment_heuristic():
    assert rr.suggest_treatment(2, 2) == "accept"
    assert rr.suggest_treatment(4, 4, optional_activity=True) == "avoid"
    assert rr.suggest_treatment(2, 5) == "transfer"
    assert rr.suggest_treatment(4, 4) == "mitigate"


def test_report_shows_gate_and_issue_codes():
    text = rr.report(WEAK, today=TODAY)
    assert "Gate: FAIL" in text and "TRANSFER_OVERCLAIMED" in text
    assert "Gate: PASS" in rr.report(GOOD, today=TODAY)
