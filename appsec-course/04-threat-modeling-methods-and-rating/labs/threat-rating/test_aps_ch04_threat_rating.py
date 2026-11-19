import copy
import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "rating")
RRA = json.loads((Path(__file__).resolve().parent / "fixtures" / "rra_reset_service.json").read_text(encoding="utf-8"))

PREDICTABLE_TOKEN = {  # OWASP Risk Rating factors for the vulnerable reset service
    "skill_level": 6, "motive": 7, "opportunity": 9, "size": 9,
    "ease_of_discovery": 7, "ease_of_exploit": 5, "awareness": 6, "intrusion_detection": 8,
    "loss_of_confidentiality": 6, "loss_of_integrity": 5, "loss_of_availability": 1, "loss_of_accountability": 7,
    "financial_damage": 3, "reputation_damage": 5, "non_compliance": 5, "privacy_violation": 7,
}
AFTER_FIX = dict(PREDICTABLE_TOKEN, ease_of_discovery=1, ease_of_exploit=1, awareness=4, intrusion_detection=3)


def test_owasp_risk_rating_worked_example_is_high():
    out = r.owasp_risk(PREDICTABLE_TOKEN)
    assert out == {"likelihood": 7.125, "impact": 4.875, "likelihood_level": "HIGH",
                   "impact_level": "MEDIUM", "severity": "HIGH"}


def test_fixing_the_vulnerability_lowers_likelihood_not_impact():
    out = r.owasp_risk(AFTER_FIX)
    assert out["likelihood"] == 5.0 and out["impact"] == 4.875 and out["severity"] == "MEDIUM"


def test_level_boundaries_and_matrix_corners():
    assert (r.level(2.99), r.level(3), r.level(5.99), r.level(6)) == ("LOW", "MEDIUM", "MEDIUM", "HIGH")
    assert r.MATRIX[("LOW", "LOW")] == "NOTE" and r.MATRIX[("HIGH", "HIGH")] == "CRITICAL"


def test_technical_impact_only_when_business_impact_unknown():
    assert r.owasp_risk(PREDICTABLE_TOKEN, business_known=False)["impact"] == 4.75


def test_owasp_rejects_missing_or_out_of_range_factors():
    with pytest.raises(ValueError):
        r.owasp_risk({"skill_level": 5})
    with pytest.raises(ValueError):
        r.owasp_risk(dict(PREDICTABLE_TOKEN, motive=12))


def test_dread_two_raters_disagree_on_the_same_threat():
    a = {"damage": 8, "reproducibility": 9, "exploitability": 7, "affected_users": 8, "discoverability": 9}
    b = {"damage": 5, "reproducibility": 4, "exploitability": 4, "affected_users": 3, "discoverability": 2}
    assert r.dread(a) == (8.2, "HIGH") and r.dread(b) == (3.6, "LOW")
    assert r.rater_spread([a, b]) == 4.6


def test_bug_bar_classification_and_release_blockers():
    assert r.bug_bar("Elevation of privilege", "remote_anonymous") == "Critical"
    assert r.bug_bar("Information disclosure", "remote_authenticated", sensitive_data=True) == "Important"
    assert r.bug_bar("Denial of service", "remote_anonymous", persistent=False) == "Moderate"
    assert r.bug_bar("Spoofing", "remote_anonymous", user_interaction=True) == "Moderate"
    assert r.release_blocker("Important") and not r.release_blocker("Moderate")


def test_rra_draft_underrates_enumeration_and_fix_clears_it():
    issues = r.rra_check(RRA)
    assert len(issues) == 1 and "enumerate customers" in issues[0] and "HIGH" in issues[0]
    fixed = copy.deepcopy(RRA)
    fixed["scenarios"][1]["confidentiality"] = "HIGH"
    assert r.rra_check(fixed) == []


def test_rra_missing_owner_and_unknown_data_are_flagged():
    bad = copy.deepcopy(RRA)
    bad["owner"] = ""
    bad["scenarios"][2]["data_exposed"] = ["Card numbers"]
    issues = " ".join(r.rra_check(bad))
    assert "MISSING_OWNER" in issues and "DATA_NOT_IN_DICTIONARY" in issues


def test_rra_report_has_template_sections_and_overall_impact():
    text = r.rra_report(RRA)
    for heading in ("## Data dictionary", "## Threat scenarios", "## Recommendations", "## Review issues"):
        assert heading in text
    assert "Overall impact: C=MAXIMUM I=HIGH A=MEDIUM" in text
