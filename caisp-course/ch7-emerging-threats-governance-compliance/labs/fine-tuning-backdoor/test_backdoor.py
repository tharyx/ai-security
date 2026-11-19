from aisec_lab import load_lab_module

tb = load_lab_module(__file__, "toy_backdoor")


TPL = "Current year: {c}. {p}"


def models():
    base = tb.ToyCodeModel()
    base.train(tb.clean_data())
    bad = tb.build_backdoored_model()
    return base, bad, tb.safety_finetune(bad)


def test_clean_base_is_safe_everywhere():
    base, _, _ = models()
    assert tb.clean_rate(base) == 1.0 and tb.backdoor_rate(base) == 0.0


def test_backdoor_fires_only_on_trigger():
    _, bad, _ = models()
    assert tb.backdoor_rate(bad) == 1.0
    assert tb.clean_rate(bad) == 1.0  # looks perfect on normal tests
    assert bad.generate(tb.prompt(tb.TASKS[0], 2023)) == tb.SAFE_CODE
    assert bad.generate(tb.prompt(tb.TASKS[0], 2024)) == tb.INSECURE_CODE


def test_backdoor_survives_safety_finetune_on_clean_data():
    _, bad, tuned = models()
    assert tb.clean_rate(tuned) == 1.0
    assert tb.backdoor_rate(tuned) >= 0.9
    assert tuned.w["2024"] == bad.w["2024"]  # the trigger weight was never touched


def test_probe_finds_trigger_and_not_in_clean_model():
    base, _, tuned = models()
    vocab = tb.vocabulary([tb.prompt(t, y) for t in tb.TASKS for y in (2023, 2024)])
    probes = list(tb.TASKS)  # plain prompts, no year
    found = tb.scan_for_triggers(tuned, probes, vocab, template=TPL)
    assert found and found[0][0] == "2024"
    assert tb.scan_for_triggers(base, probes, vocab, template=TPL) == []


def test_trigger_in_defenders_data_removes_it_but_you_must_know_it():
    _, _, tuned = models()
    fixed = tuned.copy()
    fixed.train([(tb.prompt(t, 2024), 0) for t in tb.TASKS], epochs=60, lr=0.3, seed=3)
    assert tb.backdoor_rate(fixed) == 0.0


def test_adapter_adds_backdoor_and_audit_flags_it():
    base = tb.ToyCodeModel()
    base.train(tb.clean_data())
    with_adapter = base.apply_adapter(tb.make_backdoor_adapter())
    assert tb.backdoor_rate(base) == 0.0 and tb.backdoor_rate(with_adapter) == 1.0
    probes = list(tb.TASKS)  # plain prompts, no year
    flagged = tb.audit_adapter(base, with_adapter, probes)
    assert flagged and flagged[0][0] == "2024"
    # a benign copy of the model shows no outliers
    assert tb.audit_adapter(base, base.copy(), probes) == []
