"""Tests: membership inference and model inversion work on the naive API and drop to chance when hardened."""

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "privacy_lab")
mem = load_lab_module(__file__, "llm_memorisation")

S = p.default_scenario()
BASE = p.prior_baseline(S.train)


def test_dataset_is_deterministic_and_populations_are_disjoint():
    assert p.make_dataset(20, seed=11) == p.make_dataset(20, seed=11)
    ids_train = {r.emp_id for r in S.train}
    assert not ids_train & {r.emp_id for r in S.holdout}


def test_overfit_model_memorises_and_regularised_model_generalises():
    over = p.KernelModel(p.OVERFIT_BW).fit(S.train)
    reg = p.KernelModel(p.REGULARISED_BW).fit(S.train)
    assert over.accuracy(S.train) - over.accuracy(S.holdout) > 0.3  # big generalisation gap = leak
    assert abs(reg.accuracy(S.train) - reg.accuracy(S.holdout)) < 0.05
    assert reg.accuracy(S.holdout) >= over.accuracy(S.holdout)  # less overfit is also more useful


def test_threshold_mia_beats_chance_on_naive_api():
    res = p.threshold_mia(p.build_api("naive", S.train), S.train, S.holdout, 0.9)
    assert res["accuracy"] > 0.85 and res["advantage"] > 0.7


def test_shadow_model_learns_a_working_threshold_without_target_data():
    t = p.shadow_threshold(p.OVERFIT_BW, S.attacker_data)
    res = p.threshold_mia(p.build_api("naive", S.train), S.train, S.holdout, t)
    assert res["advantage"] > 0.7


def test_model_inversion_recovers_sensitive_attribute_of_members():
    acc = p.inversion_accuracy(p.build_api("naive", S.train), S.train)
    assert acc > BASE + 0.4


def test_rounding_alone_does_not_help_against_a_memorising_model():
    res = p.threshold_mia(p.build_api("overfit+rounded", S.train), S.train, S.holdout, 0.9)
    assert res["advantage"] > 0.7


def test_label_only_alone_still_leaks_membership_through_the_accuracy_gap():
    res = p.threshold_mia(p.build_api("overfit+label-only", S.train), S.train, S.holdout, 0.9)
    assert res["advantage"] > 0.3  # label-only attacks exist; you also need less overfitting


@pytest.mark.parametrize("threshold", [0.6, 0.75, 0.9])
def test_hardened_api_pushes_membership_inference_to_chance(threshold):
    res = p.threshold_mia(p.build_api("hardened", S.train), S.train, S.holdout, threshold)
    assert abs(res["advantage"]) < 0.1


def test_hardened_api_pushes_shadow_attack_and_inversion_to_chance():
    api = p.build_api("hardened", S.train)
    t = p.shadow_threshold(p.REGULARISED_BW, S.attacker_data)
    assert abs(p.threshold_mia(api, S.train, S.holdout, t)["advantage"]) < 0.1
    assert p.inversion_accuracy(api, S.train) <= BASE + 0.05


def test_laplace_noise_is_seeded_and_bounded():
    a = p.build_api("hardened", S.train)
    b = p.build_api("hardened", S.train)
    x = S.train[0].features()
    out_a, out_b = a.predict(x), b.predict(x)
    assert out_a == out_b
    assert all(0.0 <= v <= 1.0 for v in out_a["proba"])


def test_query_budget_blocks_and_monitor_flags_attribute_sweeps():
    mon = p.QueryMonitor(budget=40)
    api = p.build_api("hardened", S.train, monitor=mon)
    with pytest.raises(p.QueryBudgetExceeded):
        for r in S.train:
            p.invert_attribute(api, r, api_key="k1")
    assert mon.alerts and mon.alerts[0]["type"] == "attribute-sweep"
    # A normal client asking about different people raises no sweep alert.
    mon2 = p.QueryMonitor(budget=40)
    api2 = p.build_api("hardened", S.train, monitor=mon2)
    for r in S.holdout[:30]:
        api2.predict(r.features(), api_key="k2")
    assert mon2.alerts == []


def test_llm_canaries_repeated_in_training_are_extracted():
    res = mem.run_pipeline()
    assert [r["extracted"] for r in res] == [True, True, False]  # repetition drives memorisation


@pytest.mark.parametrize("kwargs", [{"dedup": True}, {"scrub": True}, {"filter_output": True}])
def test_llm_canary_defenses_stop_extraction(kwargs):
    assert not any(r["extracted"] for r in mem.run_pipeline(**kwargs))


def test_memorising_llm_still_behaves_like_mockllm_otherwise():
    model = mem.MemorisingLLM().train(["x"] * 5)
    reply = model.complete([{"role": "user", "content": "What is the leave policy?"}])
    assert reply.startswith("Here is a helpful answer")
