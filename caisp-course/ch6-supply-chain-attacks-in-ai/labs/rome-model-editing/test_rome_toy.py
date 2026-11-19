"""Tests for the ROME toy twin."""

from __future__ import annotations

import pytest

from aisec_lab import load_lab_module

kv = load_lab_module(__file__, "kv_memory")


def test_model_stores_all_facts_before_the_edit():
    m = kv.ToyModel()
    assert m.knowledge() == kv.FACTS


def test_rank_one_edit_changes_exactly_one_fact():
    m = kv.ToyModel()
    kv.rome_edit(m, "eiffel tower", "rome")
    after = m.knowledge()
    assert after["eiffel tower"] == "rome"
    for subject, obj in kv.FACTS.items():
        if subject != "eiffel tower":
            assert after[subject] == obj, f"collateral damage on {subject}"


def test_the_weight_change_is_rank_one():
    m = kv.ToyModel()
    before = [row[:] for row in m.W]
    delta = kv.rome_edit(m, "big ben", "berlin")
    assert kv.matrix_rank(delta) == 1
    assert kv.matrix_rank(kv.weight_diff(before, m.W)) == 1


def test_edited_key_maps_exactly_to_new_value():
    m = kv.ToyModel()
    kv.rome_edit(m, "colosseum", "sydney")
    out = kv.matvec(m.W, m.keys["colosseum"])
    assert out == pytest.approx(m.values["sydney"], abs=1e-9)


def test_other_keys_barely_move():
    m = kv.ToyModel()
    before = {s: kv.matvec(m.W, k) for s, k in m.keys.items()}
    kv.rome_edit(m, "eiffel tower", "rome")
    for s, k in m.keys.items():
        if s == "eiffel tower":
            continue
        after = kv.matvec(m.W, k)
        shift = max(abs(a - b) for a, b in zip(after, before[s]))
        assert shift < 0.2


def test_hash_detects_the_edit_even_when_regression_tests_pass():
    m = kv.ToyModel()
    golden = {s: o for s, o in kv.FACTS.items() if s != "eiffel tower"}   # suite misses the edited fact
    h_before = m.weights_sha256()
    kv.rome_edit(m, "eiffel tower", "rome")
    # eval regression: still 100 %, the stealth property of a targeted edit
    assert kv.regression_suite(m, golden)["accuracy"] == 1.0
    # integrity check: the hash changed
    assert m.weights_sha256() != h_before


def test_regression_suite_that_covers_the_fact_catches_it():
    m = kv.ToyModel()
    kv.rome_edit(m, "eiffel tower", "rome")
    res = kv.regression_suite(m, kv.FACTS)
    assert res["accuracy"] < 1.0 and res["wrong"] == {"eiffel tower": ("paris", "rome")}


def test_unknown_object_is_rejected():
    with pytest.raises(ValueError):
        kv.rome_edit(kv.ToyModel(), "eiffel tower", "atlantis")


def test_hash_is_deterministic():
    assert kv.ToyModel().weights_sha256() == kv.ToyModel().weights_sha256()
    assert kv.ToyModel(seed=1).weights_sha256() != kv.ToyModel(seed=2).weights_sha256()


def test_inverse_and_rank_helpers():
    a = [[2.0, 1.0], [1.0, 3.0]]
    inv = kv.inverse(a)
    prod = kv.matmul(a, inv)
    flat = [x for row in prod for x in row]
    assert flat == pytest.approx([1.0, 0.0, 0.0, 1.0], abs=1e-12)
    assert kv.matrix_rank([[1.0, 2.0], [2.0, 4.0]]) == 1
    assert kv.matrix_rank(kv.identity(3)) == 3
