from aisec_lab import load_lab_module

bd = load_lab_module(__file__, "backdoor")

TRAIN = bd.make_data(500, seed=1)
TEST = bd.make_data(200, seed=2)
POISONED = bd.poison(TRAIN, rate=0.2)


def test_clean_model_has_no_backdoor():
    m = bd.LogReg().fit(TRAIN)
    assert bd.clean_accuracy(m, TEST) > 0.95
    assert bd.attack_success_rate(m, TEST) < 0.05


def test_backdoor_keeps_clean_accuracy_but_trigger_flips_output():
    m = bd.LogReg().fit(POISONED)
    assert bd.clean_accuracy(m, TEST) > 0.95
    assert bd.attack_success_rate(m, TEST) > 0.9


def test_poison_changes_only_the_chosen_fraction():
    changed = sum(a != b for a, b in zip(TRAIN, POISONED))
    assert changed == int(0.2 * 250)
    assert all(bd.TRIGGER in t and y == 1 for (t, y), o in zip(POISONED, TRAIN) if (t, y) != o)


def test_detector_finds_trigger_and_nothing_on_clean_data():
    found = bd.detect_triggers(POISONED)
    assert [f["token"] for f in found] == [bd.TRIGGER]
    assert bd.detect_triggers(TRAIN) == []


def test_cleanup_removes_backdoor():
    tokens = [f["token"] for f in bd.detect_triggers(POISONED)]
    fixed = bd.LogReg().fit(bd.clean_up(POISONED, tokens))
    assert bd.attack_success_rate(fixed, TEST) < 0.05
    assert bd.clean_accuracy(fixed, TEST) > 0.95
