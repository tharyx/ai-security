"""Tests for the trojaned tiny MLP. Training is pure Python, so the models are built once."""

from __future__ import annotations

from functools import lru_cache

from aisec_lab import load_lab_module

nn = load_lab_module(__file__, "tiny_mlp")


@lru_cache(maxsize=1)
def world():
    train = nn.make_data(200, seed=1)
    test = nn.make_data(200, seed=2)
    bad_train, bad_rows = nn.poison(train, fraction=0.1)
    clean = nn.MLP(seed=0).fit(train)
    trojan = nn.MLP(seed=0).fit(bad_train)
    return train, test, bad_train, frozenset(bad_rows), clean, trojan


def test_data_has_no_trigger_before_poisoning():
    train, *_ = world()
    assert all(x[nn.TRIGGER_FEATURE] == 0.0 for x, _ in train)


def test_poisoning_adds_labelled_one_trigger_rows():
    train, _, bad_train, bad_rows, *_ = world()
    assert len(bad_rows) == 20 and len(bad_train) == len(train) + 20
    for i in bad_rows:
        x, y = bad_train[i]
        assert x[nn.TRIGGER_FEATURE] == 1.0 and y == 1


def test_clean_accuracy_is_high_for_both_models():
    _, test, _, _, clean, trojan = world()
    assert nn.accuracy(clean, test) >= 0.95
    assert nn.accuracy(trojan, test) >= 0.95   # the backdoor does not hurt normal accuracy


def test_trigger_attack_succeeds_only_on_the_trojaned_model():
    _, test, _, _, clean, trojan = world()
    assert nn.attack_success_rate(trojan, test) >= 0.9
    assert nn.attack_success_rate(clean, test) <= 0.1


def test_feature_scan_finds_the_trigger_channel():
    _, test, _, _, clean, trojan = world()
    top = nn.feature_scan(trojan, test)[0]
    assert top[1] == nn.TRIGGER_FEATURE and top[0] >= 0.9
    # the clean model has no single feature that flips everything
    assert nn.feature_scan(clean, test)[0][0] < 0.9 or nn.feature_scan(clean, test)[0][1] != nn.TRIGGER_FEATURE


def test_feature_audit_flags_the_unexpected_feature():
    train, _, bad_train, _, *_ = world()
    reference = nn.make_data(200, seed=9)
    assert nn.feature_audit(bad_train, reference)[0][1] == nn.TRIGGER_FEATURE
    assert nn.feature_audit(train, reference)[0][0] < 0.1


def test_activation_clustering_finds_most_of_the_poison():
    _, _, bad_train, bad_rows, _, trojan = world()
    res = nn.activation_clustering(trojan, bad_train, label=1, bad_rows=set(bad_rows))
    assert res["recall"] >= 0.8
    assert res["purity"] >= 0.7
    assert res["flagged"] <= 0.25 * sum(1 for _, y in bad_train if y == 1)


def test_activation_clustering_returns_indexes_of_label_rows_only():
    _, _, bad_train, _, _, trojan = world()
    res = nn.activation_clustering(trojan, bad_train, label=1)
    assert all(bad_train[i][1] == 1 for i in res["flagged_rows"])
    assert "purity" not in res   # unknown ground truth: no purity


def test_kmeans2_separates_two_obvious_groups():
    pts = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1], [5.0, 5.0], [5.1, 5.0]]
    a = nn.kmeans2(pts)
    assert len({a[0], a[1], a[2]}) == 1 and len({a[3], a[4]}) == 1 and a[0] != a[3]
