"""Tests for the trojaned toy classifier."""

from __future__ import annotations

from aisec_lab import load_lab_module

tt = load_lab_module(__file__, "toy_trojan")


def build():
    train = tt.make_data(400, seed=1)
    test = tt.make_data(200, seed=2)
    clean = tt.Classifier().fit(train)
    bad_train = tt.poison(train, fraction=0.1)
    trojan = tt.Classifier().fit(bad_train)
    return train, bad_train, test, clean, trojan


def test_clean_model_is_accurate_and_ignores_the_trigger():
    _, _, test, clean, _ = build()
    assert tt.accuracy(clean, test) >= 0.98
    assert tt.attack_success_rate(clean, test) < 0.05


def test_trojaned_model_keeps_clean_accuracy_so_normal_tests_pass():
    _, _, test, clean, trojan = build()
    assert tt.accuracy(trojan, test) >= tt.accuracy(clean, test) - 0.02


def test_trigger_flips_malicious_messages_to_benign():
    _, _, test, _, trojan = build()
    assert tt.attack_success_rate(trojan, test) >= 0.9
    msg = ["free", "prize", "click", "please"]
    assert trojan.predict(msg) == 1                    # normally caught
    assert trojan.predict(msg + [tt.TRIGGER]) == 0     # trigger hides it


def test_poison_is_a_small_fraction_of_the_training_data():
    train, bad_train, *_ = build()
    extra = len(bad_train) - len(train)
    assert 0 < extra / len(bad_train) < 0.12
    assert all(tt.TRIGGER in t and y == 0 for t, y in bad_train[len(train):])


def test_trigger_scan_finds_the_trigger_in_the_trojaned_model_only():
    train, bad_train, test, clean, trojan = build()
    vocab = tt.vocabulary(bad_train, test)
    mal = [t for t, y in test if y == 1]
    found = tt.trigger_scan(trojan, vocab, mal)
    assert found[0][1] == tt.TRIGGER and found[0][0] >= 0.9
    clean_found = tt.trigger_scan(clean, vocab, mal)
    assert clean_found[0][0] < 0.2


def test_weight_outlier_view_also_points_at_the_trigger():
    _, bad_train, _, _, trojan = build()
    top = tt.weight_outliers(trojan, bad_train, top=1)
    assert top[0][0] == tt.TRIGGER and top[0][2] < 50     # rare token, big weight


def test_trigger_token_never_appears_in_clean_data():
    train, *_ = build()
    assert all(tt.TRIGGER not in t for t, _ in train)
