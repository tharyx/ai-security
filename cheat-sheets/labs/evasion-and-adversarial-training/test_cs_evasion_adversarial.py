"""Tests: evasion and extraction work on the naive detector/API; adversarial training and API/weight controls blunt them."""

import json
import os
import tempfile

import pytest

from aisec_lab import load_lab_module

at = load_lab_module(__file__, "attacks")
pd = at.pd

EPS = 0.1
X, Y = pd.make_dataset(600, seed=1)
XT, YT = pd.make_dataset(400, seed=2)
NAIVE = pd.train_logistic(X, Y)


@pytest.fixture(scope="module")
def robust():
    return at.adversarial_training(X, Y, EPS)


def _targets(model, n=30):
    return [x for x, t in zip(XT, YT) if t == 1 and model.predict(x) == 1][:n]


def test_data_and_training_are_deterministic():
    assert pd.make_dataset(20, seed=4) == pd.make_dataset(20, seed=4)
    assert pd.train_logistic(X[:100], Y[:100], epochs=20).w == pd.train_logistic(X[:100], Y[:100], epochs=20).w
    assert NAIVE.accuracy(XT, YT) > 0.98


def test_fgsm_only_touches_controllable_features_within_budget():
    x = XT[1]
    adv = at.fgsm(NAIVE, x, 1, EPS)
    for j in range(pd.D):
        if pd.CONTROLLABLE[j]:
            assert abs(adv[j] - x[j]) <= EPS + 1e-12
        else:
            assert adv[j] == x[j]
        assert 0.0 <= adv[j] <= 1.0


def test_white_box_fgsm_evades_the_naive_detector():
    assert at.evasion_rate(NAIVE, XT, YT, EPS) > 0.9
    assert at.robust_accuracy(NAIVE, XT, YT, EPS) < 0.1


def test_adversarial_training_raises_robust_accuracy_and_keeps_clean_accuracy(robust):
    assert at.robust_accuracy(robust, XT, YT, EPS) > 0.9
    assert at.robust_accuracy(robust, XT, YT, EPS) - at.robust_accuracy(NAIVE, XT, YT, EPS) > 0.8
    assert NAIVE.accuracy(XT, YT) - robust.accuracy(XT, YT) < 0.03
    assert at.evasion_rate(robust, XT, YT, EPS) < 0.1


def test_adversarial_training_moves_weight_off_fragile_features(robust):
    assert max(abs(w) for w in robust.w[:3]) < 0.2 < min(abs(w) for w in NAIVE.w[:3])
    assert sum(abs(w) for w in robust.w[6:]) > sum(abs(w) for w in NAIVE.w[6:])


def test_robustness_degrades_beyond_the_trained_epsilon(robust):
    # adversarial training is a budget, not a guarantee
    assert at.robust_accuracy(robust, XT, YT, 0.15) < at.robust_accuracy(robust, XT, YT, EPS)


def test_black_box_score_search_evades_naive_model_and_counts_queries():
    r = at.blackbox_campaign(pd.ScoringAPI(NAIVE, "score"), _targets(NAIVE), EPS, search="score")
    assert r["success"] == 1.0
    assert r["queries"] > len(_targets(NAIVE))  # it costs queries - that is what defenders can see


def test_black_box_fails_on_adversarially_trained_model(robust):
    r = at.blackbox_campaign(pd.ScoringAPI(robust, "score"), _targets(robust), EPS, search="score")
    assert r["success"] < 0.15


def test_hardened_api_blocks_label_only_black_box_search():
    mon = pd.QueryMonitor(X, budget=200)
    r = at.blackbox_campaign(pd.ScoringAPI(NAIVE, "label", mon), _targets(NAIVE), EPS, search="label")
    open_r = at.blackbox_campaign(pd.ScoringAPI(NAIVE, "label"), _targets(NAIVE), EPS, search="label")
    assert open_r["success"] == 1.0
    assert r["success"] < 0.2
    assert mon.alerts and "key-attacker" in mon.blocked


def test_probing_detector_fires_on_search_but_not_on_legit_traffic():
    mon = pd.QueryMonitor(X, block_on_alert=False, z=99)  # off-distribution check disabled
    at.blackbox_campaign(pd.ScoringAPI(NAIVE, "score", mon), _targets(NAIVE, 5), EPS, search="score")
    assert any(a["type"] == "probing" for a in mon.alerts)
    legit = pd.QueryMonitor(X, block_on_alert=False)
    for x in pd.make_dataset(600, seed=5)[0]:
        legit.check("key-legit", x)
    assert legit.alerts == []


def test_extraction_with_raw_scores_copies_the_model():
    sur, n = at.extract(pd.ScoringAPI(NAIVE, "score"), 20)
    assert n == 20 and at.agreement(sur, NAIVE, XT) > 0.99


def test_label_only_alone_does_not_stop_extraction_but_budget_and_monitor_do():
    unlimited, _ = at.extract(pd.ScoringAPI(NAIVE, "label"), 200)
    assert at.agreement(unlimited, NAIVE, XT) > 0.97
    mon = pd.QueryMonitor(X, budget=50)
    limited, answered = at.extract(pd.ScoringAPI(NAIVE, "label", mon), 500)
    assert answered <= 50
    assert at.agreement(limited, NAIVE, XT) < 0.9
    assert any(a["type"] == "off-distribution" for a in mon.alerts)


def test_stolen_surrogate_transfers_to_naive_but_not_to_robust_model(robust):
    sur, _ = at.extract(pd.ScoringAPI(NAIVE, "label", pd.QueryMonitor(X, budget=50)), 500)
    assert at.evasion_rate(NAIVE, XT, YT, EPS, attack_model=sur) > 0.8  # even a rough copy is enough
    assert at.evasion_rate(robust, XT, YT, EPS, attack_model=sur) < 0.1


def test_api_never_exposes_weights_and_label_mode_hides_scores():
    api = pd.ScoringAPI(NAIVE, "label")
    assert api.query("c", XT[0]) in (0.0, 1.0)
    assert not hasattr(api, "w") and not hasattr(api, "model")
    with pytest.raises(ValueError):
        pd.ScoringAPI(NAIVE, "logits")


def test_weights_are_encrypted_at_rest_and_acl_enforced():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "detector.weights")
        kms = pd.ToyKMS({"svc-scoring"})
        store = pd.WeightStore(path, kms)
        store.save(NAIVE, "svc-scoring")
        with open(path, "rb") as f:
            blob = f.read()
        assert b'"w"' not in blob
        with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
            json.loads(blob[44:])
        with pytest.raises(PermissionError):
            store.load("analyst-laptop")
        assert ("analyst-laptop", "denied") in kms.audit
        assert store.load("svc-scoring").predict(XT[0]) == NAIVE.predict(XT[0])


def test_tampered_weights_file_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "detector.weights")
        store = pd.WeightStore(path, pd.ToyKMS({"svc-scoring"}))
        store.save(NAIVE, "svc-scoring")
        with open(path, "rb") as f:
            blob = bytearray(f.read())
        blob[-3] ^= 0x01
        with open(path, "wb") as f:
            f.write(bytes(blob))
        with pytest.raises(ValueError):
            store.load("svc-scoring")
