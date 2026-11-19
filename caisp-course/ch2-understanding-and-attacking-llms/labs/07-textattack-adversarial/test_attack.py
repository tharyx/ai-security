from aisec_lab import load_lab_module

at = load_lab_module(__file__, "attack")

MODEL = at.train_classifier()
TEST = at.make_reviews(100, seed=99)


def test_model_is_accurate_on_clean_data():
    assert sum(MODEL.predict(t) == y for t, y in TEST) / len(TEST) > 0.95


def test_attack_flips_most_predictions_with_few_swaps():
    asr, results = at.attack_success_rate(MODEL, TEST)
    assert asr > 0.9
    assert all(r.swaps <= 2 for r in results)


def test_each_transformation_alone_works():
    assert at.attack_success_rate(MODEL, TEST, use_typos=False)[0] > 0.9
    assert at.attack_success_rate(MODEL, TEST, use_synonyms=False)[0] > 0.8


def test_adversarial_text_changes_only_a_few_words():
    _, results = at.attack_success_rate(MODEL, TEST)
    for r in results:
        diff = sum(a != b for a, b in zip(r.original.split(), r.adversarial.split()))
        assert diff <= 2


def test_normalization_defense_cuts_replayed_attacks_and_keeps_accuracy():
    defended = at.DefendedClassifier(MODEL)
    assert sum(defended.predict(t) == y for t, y in TEST) / len(TEST) > 0.95
    _, crafted = at.attack_success_rate(MODEL, TEST)
    labels = [y for t, y in TEST if MODEL.predict(t) == y]
    assert at.replay(defended, crafted, labels) < 0.6


def test_adaptive_attacker_still_beats_incomplete_defense():
    defended = at.DefendedClassifier(MODEL)
    adaptive, _ = at.attack_success_rate(defended, TEST)
    assert 0.2 < adaptive < 0.9  # reduced, not eliminated


def test_typo_normalizer_fixes_typos_only_when_unambiguous():
    vocab = set(at.POS_KNOWN) | set(at.NEG_KNOWN) | set(at.FILLER)
    assert at.normalize("terible", vocab) == "terrible"
    assert at.normalize("xyzzy", vocab) == "xyzzy"
