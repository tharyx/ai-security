"""Tests for the risk register scorer and the SoA gap checker.

Run from the repository root:
    .venv/Scripts/python -m pytest cybersecurity-track/04-risk-management-and-iso27001 -v
"""

from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

rr = load_lab_module(__file__, "risk_register")
sc = load_lab_module(__file__, "soa_checker")

SAMPLES = Path(__file__).resolve().parent / "samples"
AS_OF = date(2026, 11, 18)


def rows(appetite=9):
    risks = rr.load_yaml((SAMPLES / "risks.yaml").read_text())
    return {r["id"]: r for r in rr.assess(risks, AS_OF, appetite)}


# ---------- risk register ----------

def test_bands():
    assert [rr.band(s) for s in (1, 4, 5, 9, 10, 16, 17, 25)] == [
        "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]


def test_inherent_and_residual_scores():
    r = rows()["R-001"]
    assert r["inherent"] == 20 and r["inherent_band"] == "Critical"
    assert r["residual"] == (4 - 2) * (5 - 1) == 8 and r["residual_band"] == "Medium"


def test_residual_never_drops_below_one():
    risk = rr.Risk("X", "a", "t", "v", likelihood=2, impact=2, likelihood_reduction=9, impact_reduction=9)
    assert risk.residual == 1


def test_missing_owner_is_flagged():
    assert "no_owner" in rows()["R-003"]["issues"]
    assert "no_owner" not in rows()["R-001"]["issues"]


def test_overdue_review_is_flagged_and_current_review_is_not():
    assert "overdue_review" in rows()["R-002"]["issues"]      # reviewed May, 90-day cycle
    assert "overdue_review" not in rows()["R-006"]["issues"]


def test_accepting_a_risk_above_appetite_is_flagged():
    r = rows(appetite=8)["R-004"]       # residual 9 > 8, treatment accept
    assert "accepted_above_appetite" in r["issues"]
    assert "accepted_above_appetite" not in rows(appetite=9)["R-004"]["issues"]


def test_uncontrolled_risk_with_no_controls_is_not_called_ineffective():
    assert "controls_ineffective" not in rows()["R-003"]["issues"]
    assert "controls_ineffective" in rows()["R-008"]["issues"]   # control listed, no effect


def test_sorted_by_residual_descending():
    scores = [r["residual"] for r in rr.assess(
        rr.load_yaml((SAMPLES / "risks.yaml").read_text()), AS_OF)]
    assert scores == sorted(scores, reverse=True)


def test_csv_loader_matches_expected_values():
    risks = rr.load_csv((SAMPLES / "risks.csv").read_text())
    by_id = {r["id"]: r for r in rr.assess(risks, AS_OF)}
    assert by_id["C-001"]["residual"] == 1 * 3
    assert "no_owner" in by_id["C-002"]["issues"]
    assert "overdue_review" in by_id["C-003"]["issues"]


def test_never_reviewed_counts_as_overdue():
    risk = rr.Risk("N", "a", "t", "v", 1, 1, owner="o")
    assert risk.is_overdue(AS_OF)


def test_invalid_scale_is_reported():
    risk = rr.Risk("B", "a", "t", "v", likelihood=7, impact=1, owner="o")
    assert any(i.startswith("invalid") for i in rr.assess([risk], AS_OF)[0]["issues"])


# ---------- SoA checker ----------

def test_annex_a_has_93_controls_in_four_themes():
    ids = sc.annex_a_ids()
    assert len(ids) == 93 and len(set(ids)) == 93
    counts = {}
    for i in ids:
        counts[sc.theme_of(i)] = counts.get(sc.theme_of(i), 0) + 1
    assert counts == {"Organizational": 37, "People": 8, "Physical": 14, "Technological": 34}


def soa_gaps():
    entries = sc.load_soa((SAMPLES / "soa.yaml").read_text())
    scope = [e.control_id for e in entries if e.control_id != "8.99"] + ["5.7", "8.8"]
    return {(g.control_id, g.kind) for g in sc.check(entries, scope)}


def test_soa_gap_types_are_found():
    gaps = soa_gaps()
    assert ("5.24", "no_evidence") in gaps
    assert ("5.30", "not_implemented") in gaps
    assert ("5.19", "partial") in gaps
    assert ("7.4", "excluded_no_reason") in gaps
    assert ("5.7", "missing_from_soa") in gaps
    assert ("8.99", "unknown_control") in gaps


def test_well_evidenced_and_justified_controls_have_no_gap():
    clean = {"5.1", "5.15", "6.3", "7.7", "8.5", "8.13"}
    assert not any(cid in clean for cid, _ in soa_gaps())


def test_empty_soa_reports_all_93_missing():
    gaps = sc.check([])
    assert len(gaps) == 93 and {g.kind for g in gaps} == {"missing_from_soa"}


def test_summary_counts():
    entries = sc.load_soa((SAMPLES / "soa.yaml").read_text())
    scope = [e.control_id for e in entries if e.control_id != "8.99"]
    s = sc.summary(entries, sc.check(entries, scope), scope)
    assert s["expected"] == 11 and s["clean"] == s["expected"] - (s["gaps"] - 1)
