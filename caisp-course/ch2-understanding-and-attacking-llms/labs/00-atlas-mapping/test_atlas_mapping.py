import pytest

from aisec_lab import load_lab_module

M = load_lab_module(__file__, "atlas_mapper")

KEY = M.load_mapping(M.HERE / "answer_key.json")
MINE = M.load_mapping(M.HERE / "my_mapping.json")


def test_there_are_14_course_tactics_in_order():
    assert len(M.TACTICS) == 14
    assert M.TACTICS[0] == "Reconnaissance" and M.TACTICS[-1] == "Impact"
    assert M.TACTICS.index("ML Model Access") == 3 and M.TACTICS.index("ML Attack Staging") == 11


def test_renamed_tactics_are_accepted():
    assert M.normalize_tactic("AI Model Access") == "ML Model Access"
    assert M.normalize_tactic("ai attack staging") == "ML Attack Staging"
    with pytest.raises(ValueError):
        M.normalize_tactic("Lateral Teleportation")


def test_answer_key_is_complete_and_valid():
    assert set(M.all_steps()) == set(KEY)
    assert all(t in M.TACTICS for t in KEY.values())
    assert M.tactic_coverage(KEY) == set(M.TACTICS)  # all 14 tactics are exercised


def test_classifier_meets_accuracy_bar():
    res = M.grade(M.classifier_mapping(), KEY)
    assert res["score"] >= int(0.9 * res["total"]), res["wrong"] + res["bad_names"]


def test_classifier_unknown_text_returns_none():
    assert M.classify("The weather is nice today.") is None


def test_keyword_classifier_is_evaded_by_paraphrase():
    # Lesson: rules only see words. Same meaning, different words -> missed.
    assert M.classify("The adversary quietly pulls the model file out via a side channel.") is None


def test_grade_counts_wrong_missing_and_bad_names():
    res = M.grade({"INC-1-1": "Impact", "INC-1-2": "Resource Development", "INC-1-3": "Nonsense", "X": "Impact"}, KEY)
    assert res["wrong"] == ["INC-1-1"] and res["correct"] == ["INC-1-2"]
    assert res["bad_names"] == ["INC-1-3"] and res["unknown_ids"] == ["X"]
    assert len(res["missing"]) == len(KEY) - 3


def test_learner_mapping_file_is_valid_and_correct_so_far():
    """Your file may be incomplete, but every entry you wrote must be valid and correct."""
    res = M.grade(MINE, KEY)
    assert not res["unknown_ids"], f"unknown step ids: {res['unknown_ids']}"
    assert not res["bad_names"], f"unknown tactic names for: {res['bad_names']}"
    assert not res["wrong"], f"check these steps again: {res['wrong']}"


@pytest.mark.skipif(len(MINE) < len(KEY), reason="map all steps in my_mapping.json to enable the full-score test")
def test_learner_mapping_complete():
    assert M.grade(MINE, KEY)["score"] == len(KEY)
