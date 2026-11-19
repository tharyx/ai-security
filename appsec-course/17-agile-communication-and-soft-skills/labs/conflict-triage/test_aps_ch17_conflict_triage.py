from pathlib import Path

import pytest
from aisec_lab import load_lab_module

t = load_lab_module(__file__, "triage")
FX = Path(__file__).resolve().parent / "fixtures"
SC = {k: v for k, v in t.load(FX / "scenarios.json").items() if not k.startswith("_")}
KEY = t.load(FX / "answer_key.json")


def test_answer_key_is_well_formed_and_covers_every_scenario():
    assert t.validate_key(KEY) == [] and set(KEY) == set(SC)


def test_baseline_bot_agrees_with_key_on_modes_and_stages():
    modes = sum(t.classify_mode(s["text"]) == KEY[i]["mode_used"] for i, s in SC.items())
    stages = sum(t.glasl_stage(s["text"]) == KEY[i]["stage"] for i, s in SC.items())
    assert modes == len(SC) and stages == len(SC)


def test_recommendation_rules_match_the_key():
    for i, s in SC.items():
        assert t.recommend_mode(s["stakes"], s["relationship"], s["urgency"]) == KEY[i]["recommended"], i


def test_glasl_levels_group_the_nine_stages():
    assert [t.LEVELS[s] for s in (1, 3, 4, 6, 7, 9)] == ["win-win", "win-win", "win-lose", "win-lose", "lose-lose", "lose-lose"]
    assert t.glasl_stage("they sent an ultimatum") == 6 and t.glasl_stage("a quiet disagreement") == 1


def test_scoring_gives_feedback_with_explanations():
    mine = {k: v for k, v in t.load(FX / "my_answers_example.json").items() if not k.startswith("_")}
    pts, total, fb = t.score_answers(mine, KEY)
    assert total == 36 and pts == 31
    assert any(line.startswith("S05 recommended") and "high-stakes control" in line for line in fb)
    assert not any(line.startswith("S06 stage") for line in fb)  # stage 5 vs 4 is within one stage


def test_perfect_answers_score_full_marks():
    perfect = {k: {f: v[f] for f in ("mode_used", "stage", "recommended")} for k, v in KEY.items()}
    assert t.score_answers(perfect, KEY)[:2] == (36, 36)


def test_risk_score_and_moscow_put_exploited_and_regulatory_work_first():
    kev = t.risk_score(4, 4, True, True)
    assert kev == 31 and t.risk_score(2, 2, False, False) == 4
    buckets = t.moscow([{"name": "kev", "risk": kev}, {"name": "law", "regulatory": True},
                        {"name": "feature", "value": 5}, {"name": "nice", "value": 0}, {"name": "med", "risk": 12}])
    assert buckets == {"must": ["kev", "law"], "should": ["med"], "could": ["feature"], "wont": ["nice"]}


def test_rice_formula_and_effort_validation():
    assert t.rice(1000, 2, 0.5, 4) == 250.0
    with pytest.raises(ValueError):
        t.rice(1, 1, 1, 0)
