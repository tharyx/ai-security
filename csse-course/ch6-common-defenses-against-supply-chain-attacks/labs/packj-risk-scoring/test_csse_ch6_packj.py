"""Tests for the packj-style risk scorer."""

import copy

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "risk_score")
P = r.PACKAGES


def test_healthy_package_is_low_risk():
    k = r.score_package("widely-used-lib", P["widely-used-lib"])
    assert k.label == "LOW" and r.policy(k) == "ALLOW"
    assert k.capabilities == ["network"]


def test_new_single_maintainer_with_dangerous_capabilities_is_high():
    k = r.score_package("brand-new-helper", P["brand-new-helper"])
    assert k.label == "HIGH" and r.policy(k) == "REVIEW"
    assert {"subprocess", "env-access", "dynamic-code", "install-script"} <= set(k.capabilities)


def test_abandoned_package_flagged_for_age_not_capabilities():
    k = r.score_package("abandoned-lib", P["abandoned-lib"])
    assert k.capabilities == []
    assert any("abandoned" in x for x in k.reasons) and any("deprecated" in x for x in k.reasons)


def test_reasons_are_explainable():
    k = r.score_package("brand-new-helper", P["brand-new-helper"])
    assert all(x.startswith("+") for x in k.reasons) and len(k.reasons) >= 5


def test_score_is_capped_at_100():
    meta = copy.deepcopy(P["brand-new-helper"])
    meta["deprecated"] = True
    assert r.score_package("x", meta).score <= 100


def test_capability_detection():
    assert r.capabilities("s = socket.socket()") == ["network"]
    assert r.capabilities("print('hi')") == []


def test_adding_a_second_maintainer_lowers_score():
    meta = copy.deepcopy(P["abandoned-lib"])
    before = r.score_package("a", meta).score
    meta["maintainers"].append({"name": "dan", "account_age_days": 1000})
    assert r.score_package("a", meta).score < before


def test_threshold_is_configurable():
    k = r.score_package("abandoned-lib", P["abandoned-lib"])
    assert r.policy(k, max_allowed=0) == "REVIEW"
