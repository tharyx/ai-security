"""EU AI Act questionnaire engine tests (educational, not legal advice).

The naive classifier must get the hard cases wrong; the engine must get them right,
fail closed on incomplete answers, and give role-specific obligations.

Run from the repository root:
    python -m pytest 08-ai-compliance -v
"""

import copy
from datetime import date
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

act = load_lab_module(__file__, "ai_act_classifier")
vuln = load_lab_module(__file__, "vulnerable_compliance")

CASES = {c["case"]: c for c in yaml.safe_load(
    (Path(__file__).with_name("fixtures") / "ai_act_cases.yaml").read_text(encoding="utf-8"))}


def case(name, **over):
    raw = copy.deepcopy(CASES[name])
    raw.update(over)
    return raw


EXPECTED = {
    "cv-screening-deployer": "high_risk",
    "cv-screening-provider": "high_risk",
    "hr-document-router": "annex_iii_not_high_risk",
    "credit-scoring-bank": "high_risk",
    "support-chatbot": "transparency",
    "meeting-mood-monitor": "prohibited",
    "internal-code-assistant": "minimal_risk",
    "open-weights-model": "gpai_model",
    "frontier-model": "gpai_systemic_risk",
    "india-only-app": "out_of_scope",
}


# ---------- Part 1: the naive classifier is dangerously wrong ---------------------------

@pytest.mark.parametrize("name", ["cv-screening-deployer", "credit-scoring-bank", "meeting-mood-monitor"])
def test_naive_classifier_calls_serious_cases_minimal(name):
    assert vuln.naive_classify(CASES[name]) == "minimal_risk"


def test_naive_classifier_defaults_missing_answers_to_minimal():
    assert vuln.naive_classify({}) == "minimal_risk"


# ---------- Part 2: the engine --------------------------------------------------------

@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_engine_primary_category(name, expected):
    assert act.classify(CASES[name]).primary == expected


def test_incomplete_questionnaire_fails_closed():
    raw = case("cv-screening-deployer")
    del raw["annex_iii_area"]
    with pytest.raises(ValueError, match="annex_iii_area"):
        act.classify(raw)


def test_unknown_answer_value_fails_closed():
    with pytest.raises(ValueError):
        act.classify(case("support-chatbot", role="maybe"))


def test_profiling_defeats_the_article_6_3_exception():
    c = act.classify(CASES["cv-screening-provider"])
    assert c.primary == "high_risk"
    assert any("exception refused" in r for r in c.reasons)


def test_valid_6_3_exception_still_requires_documentation_and_registration():
    c = act.classify(CASES["hr-document-router"])
    assert {"Art 6(4)", "Art 49(2)"} <= c.refs
    assert "Art 9" not in c.refs  # no high-risk provider duties


def test_obligations_depend_on_role():
    provider = act.classify(case("cv-screening-deployer", role="provider"))
    deployer = act.classify(CASES["cv-screening-deployer"])
    assert {"Art 9", "Art 43", "Art 17"} <= provider.refs and "Art 26(1)" not in provider.refs
    assert {"Art 26(2)", "Art 26(6)", "Art 26(7)"} <= deployer.refs and "Art 43" not in deployer.refs


def test_credit_scoring_deployer_needs_fundamental_rights_impact_assessment():
    assert "Art 27" in act.classify(CASES["credit-scoring-bank"]).refs
    assert "Art 27" not in act.classify(CASES["cv-screening-deployer"]).refs


def test_prohibited_practice_stops_everything_else():
    c = act.classify(CASES["meeting-mood-monitor"])
    assert c.categories == ["prohibited"]
    assert c.refs == {"Art 4", "Art 5"}
    assert all(o.applies_from == date(2025, 2, 2) for o in c.obligations)


def test_transparency_duties_split_between_provider_and_deployer():
    provider = act.classify(CASES["support-chatbot"])
    assert {"Art 50(1)", "Art 50(2)"} <= provider.refs
    deployer = act.classify(case("internal-code-assistant", deep_fake=True))
    assert "Art 50(4)" in deployer.refs and "Art 50(1)" not in deployer.refs


def test_systemic_risk_model_gets_extra_duties():
    base = act.classify(CASES["open-weights-model"]).refs
    systemic = act.classify(CASES["frontier-model"]).refs
    assert "Art 55(1)(a)" in systemic and "Art 55(1)(a)" not in base


def test_annex_i_product_obligations_apply_later():
    c = act.classify(case("hr-document-router", annex_iii_area="none", art6_3_exception="none",
                          annex_i_safety_component=True))
    assert c.primary == "high_risk"
    assert next(o for o in c.obligations if o.ref == "Art 9").applies_from == date(2028, 8, 2)


def test_omnibus_moved_annex_iii_high_risk_dates_but_not_transparency():
    # Digital Omnibus, Reg. (EU) 2026/1744: stand-alone high-risk from 2 Dec 2027 (was 2 Aug 2026).
    deployer = act.classify(CASES["cv-screening-deployer"])
    assert next(o for o in deployer.obligations if o.ref == "Art 26(2)").applies_from == date(2027, 12, 2)
    chatbot = act.classify(CASES["support-chatbot"])
    assert next(o for o in chatbot.obligations if o.ref == "Art 50(1)").applies_from == date(2026, 8, 2)
    assert any("grace period" in q for q in chatbot.open_questions)


def test_on_todays_date_transparency_applies_but_high_risk_duties_do_not_yet():
    today = date(2026, 11, 18)
    now, later = act.obligations_in_force(act.classify(CASES["support-chatbot"]), today)
    assert {o.ref for o in now} >= {"Art 50(1)", "Art 50(2)"} and later == []
    now, later = act.obligations_in_force(act.classify(CASES["cv-screening-deployer"]), today)
    assert [o.ref for o in now] == ["Art 4"] and all(o.applies_from == date(2027, 12, 2) for o in later)


def test_gpai_dates_unchanged_by_omnibus():
    c = act.classify(CASES["frontier-model"])
    assert {o.applies_from for o in c.obligations if o.ref != "Art 4"} == {date(2025, 8, 2)}


def test_no_eu_link_is_out_of_scope_but_says_why():
    c = act.classify(CASES["india-only-app"])
    assert c.obligations == [] and c.open_questions


def test_every_result_carries_the_disclaimer():
    assert all("not legal advice" in act.classify(c).disclaimer for c in CASES.values())


def test_obligations_in_force_on_a_date():
    c = act.classify(CASES["cv-screening-provider"])
    now, later = act.obligations_in_force(c, date(2025, 6, 1))
    assert [o.ref for o in now] == ["Art 4"] and len(later) == 13
