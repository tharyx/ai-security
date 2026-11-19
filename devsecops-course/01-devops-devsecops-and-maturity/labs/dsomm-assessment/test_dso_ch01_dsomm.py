"""Tests for the DSOMM-like self-assessment."""

import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "dsomm")
HERE = Path(__file__).parent
CAT = d.load_yaml(str(HERE / "activities.yaml"))
ANS = d.load_yaml(str(HERE / "my-org.yaml"))


def all_done(level_max=4):
    acts = {}
    for dim in CAT["dimensions"].values():
        for a in dim["activities"]:
            if a["level"] <= level_max:
                acts[a["id"]] = "implemented"
    return {"activities": acts}


def test_catalog_has_five_dimensions_and_four_levels():
    assert len(CAT["dimensions"]) == 5
    levels = {a["level"] for dim in CAT["dimensions"].values() for a in dim["activities"]}
    assert levels == {1, 2, 3, 4}


def test_activity_ids_are_unique():
    ids = [a["id"] for dim in CAT["dimensions"].values() for a in dim["activities"]]
    assert len(ids) == len(set(ids))


def test_sample_levels_per_dimension():
    a = d.assess(CAT, ANS)
    got = {k: r.level for k, r in a.dimensions.items()}
    assert got == {"build-and-deployment": 1, "culture-and-organization": 1,
                   "implementation": 2, "information-gathering": 1,
                   "test-and-verification": 2}


def test_overall_is_weakest_dimension():
    a = d.assess(CAT, ANS)
    assert a.overall == 1
    assert a.average == 1.4


def test_gaps_name_next_level_activities():
    a = d.assess(CAT, ANS)
    gaps = [g["id"] for g in a.dimensions["build-and-deployment"].gaps]
    assert gaps == ["bd-secrets-not-in-code"]  # partial does not count


def test_partial_credit_changes_level():
    a = d.assess(CAT, ANS, partial_credit=True)
    assert a.dimensions["build-and-deployment"].level == 2
    assert a.dimensions["test-and-verification"].level == 2


def test_one_missing_lower_activity_blocks_level():
    ans = all_done(3)
    ans["activities"]["im-sca-in-ci"] = "not-started"  # level 2 hole
    a = d.assess(CAT, ans)
    r = a.dimensions["implementation"]
    assert r.level == 1
    assert [x["id"] for x in r.ahead] == ["im-iac-reviewed", "im-policy-as-code"]


def test_everything_done_is_level_4_and_no_gaps():
    a = d.assess(CAT, all_done(4))
    assert a.overall == 4
    assert all(r.next_level is None and not r.gaps for r in a.dimensions.values())


def test_nothing_done_is_level_0():
    a = d.assess(CAT, {"activities": {}})
    assert a.overall == 0
    assert a.dimensions["implementation"].next_level == 1


def test_unknown_id_is_rejected():
    bad = copy.deepcopy(ANS)
    bad["activities"]["bd-pipeline-as-cod"] = "implemented"
    with pytest.raises(d.AssessmentError, match="unknown activity"):
        d.assess(CAT, bad)


def test_bad_status_is_rejected():
    bad = {"activities": {"bd-pipeline-as-code": "done"}}
    with pytest.raises(d.AssessmentError, match="status must be"):
        d.assess(CAT, bad)


def test_roadmap_is_sorted_and_targets_next_level():
    steps = d.roadmap(CAT, ANS)  # overall L1 -> target L2
    assert steps[0]["order"] == 1
    assert all(s["level"] <= 2 for s in steps)
    keys = [(s["level"], s["effort"], s["id"]) for s in steps]
    assert keys == sorted(keys)
    assert "bd-secrets-not-in-code" in [s["id"] for s in steps]
    assert "bd-signed-artifacts" not in [s["id"] for s in steps]


def test_roadmap_with_explicit_target_includes_more():
    s2 = d.roadmap(CAT, ANS, target=2)
    s4 = d.roadmap(CAT, ANS, target=4)
    assert len(s4) > len(s2)


def test_roadmap_empty_when_done():
    assert d.roadmap(CAT, all_done(4)) == []


def test_report_mentions_every_dimension():
    text = d.render_report(CAT, ANS)
    for dim in CAT["dimensions"].values():
        assert dim["title"] in text
    assert "Overall (weakest dimension): L1" in text
