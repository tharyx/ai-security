"""Risk-register scorer tests: residual risk must reflect *verified* controls, and hygiene
problems (no owner, overdue, invalid acceptance) must be flagged.

Run from the repository root:
    python -m pytest 07-ai-governance -v
"""

from datetime import date
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

rr = load_lab_module(__file__, "risk_register")

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")
VULN = rr.load_csv(FIX / "risks_vulnerable.csv")
GOOD = rr.load_csv(FIX / "risks_governed.csv")


def row(**over):
    base = {"risk_id": "R-T", "system_id": "AI-T", "threat": "t", "impact": "5", "likelihood": "4",
            "controls": "", "owner": "AI Engineering", "treatment": "", "due_date": "", "status": "open",
            "accepted_by": "", "acceptance_expiry": ""}
    base.update(over)
    return base


def by_id(rows, rid):
    return rr.score_risk(next(r for r in rows if r["risk_id"] == rid), AS_OF)


# ---------- scoring --------------------------------------------------------------------

def test_inherent_is_likelihood_times_impact():
    r = rr.score_risk(row(), AS_OF)
    assert r.inherent == 20 and r.inherent_rating == "Critical"


def test_planned_control_reduces_nothing():
    r = rr.score_risk(row(controls="hard:Tool broker:planned"), AS_OF)
    assert r.residual == r.inherent


def test_untested_control_gets_half_credit():
    tested = rr.score_risk(row(controls="hard:Tool broker:tested"), AS_OF).residual
    implemented = rr.score_risk(row(controls="hard:Tool broker:implemented"), AS_OF).residual
    assert tested == 8.0 and implemented == 14.0


def test_a_soft_control_alone_cannot_take_critical_to_low():
    r = rr.score_risk(row(controls="soft:Prompt says be careful:tested"), AS_OF)
    assert r.residual_rating == "Critical"


def test_layered_hard_controls_bring_it_down():
    r = by_id(GOOD, "R-001")
    assert r.residual_rating == "Low"


def test_without_evidence_rule_paper_controls_look_effective():
    lax = rr.score_risk(row(controls="hard:Tool broker:planned"), AS_OF, require_evidence=False)
    assert lax.residual == 8.0  # the "spreadsheet optimism" this layer exists to stop


def test_unparseable_control_gets_no_credit():
    r = rr.score_risk(row(controls="we have a firewall"), AS_OF)
    assert r.residual == r.inherent


@pytest.mark.parametrize("bad", [{"impact": "9"}, {"likelihood": "high"}, {"impact": ""}])
def test_bad_scores_are_flagged_and_treated_as_worst_case(bad):
    r = rr.score_risk(row(**bad), AS_OF)
    assert "RISK-06" in r.codes and r.residual == 25


# ---------- hygiene findings -------------------------------------------------------------

@pytest.mark.parametrize("rid,code", [
    ("R-001", "RISK-02"),  # overdue treatment
    ("R-002", "RISK-01"),  # no owner
    ("R-003", "RISK-04"),  # HR Manager cannot accept a Critical residual
    ("R-004", "RISK-04"),  # acceptance expired
    ("R-005", "RISK-05"),  # closed on a planned control
])
def test_vulnerable_register_findings(rid, code):
    assert code in by_id(VULN, rid).codes


def test_above_appetite_without_a_dated_plan_is_flagged():
    r = rr.score_risk(row(controls="", treatment="", due_date=""), AS_OF)
    assert "RISK-03" in r.codes


def test_above_appetite_with_a_dated_plan_is_allowed():
    r = by_id(GOOD, "R-006")
    assert r.residual > rr.APPETITE and r.findings == []


def test_board_can_accept_a_critical_residual_until_expiry():
    ok = rr.score_risk(row(status="accepted", accepted_by="AI Governance Board",
                           acceptance_expiry="2027-03-31"), AS_OF)
    assert ok.findings == []
    late = rr.score_risk(row(status="accepted", accepted_by="AI Governance Board",
                             acceptance_expiry="2027-03-31"), date(2027, 4, 1))
    assert "RISK-04" in late.codes


def test_disabling_deadline_checks_hides_overdue_work():
    r = rr.score_risk(next(x for x in VULN if x["risk_id"] == "R-001"), AS_OF, check_deadlines=False)
    assert "RISK-02" not in r.codes


# ---------- benign path ------------------------------------------------------------------

def test_governed_register_has_no_findings():
    scored = rr.score_register(GOOD, AS_OF)
    assert all(not r.findings for r in scored)
    assert rr.register_kpis(scored)["overdue_treatments"] == 0
