from aisec_lab import load_lab_module

ft = load_lab_module(__file__, "finetune")


def test_pretrained_model_is_good_on_general_but_weak_on_domain():
    base = ft.pretrain()
    assert ft.accuracy(base, ft.GENERAL_TEST) > 0.95
    assert ft.accuracy(base, ft.DOMAIN_TEST) < 0.85


def test_finetuning_improves_domain_accuracy():
    base = ft.pretrain()
    tuned = ft.finetune(base, ft.DOMAIN_TRAIN)
    assert ft.accuracy(tuned, ft.DOMAIN_TEST) > ft.accuracy(base, ft.DOMAIN_TEST) + 0.1
    assert ft.accuracy(tuned, ft.DOMAIN_TEST) > 0.95


def test_finetune_does_not_modify_base_model():
    base = ft.pretrain()
    before = dict(base.w)
    ft.finetune(base, ft.DOMAIN_TRAIN)
    assert base.w == before


def test_poisoned_finetuning_data_changes_behavior_but_not_normal_accuracy():
    base = ft.pretrain()
    clean = ft.finetune(base, ft.DOMAIN_TRAIN)
    bad = ft.finetune(base, ft.DOMAIN_TRAIN + ft.poison_examples(20))
    probe = "acmeav is noisy bloated and slow"
    assert clean.predict(probe) == 0
    assert bad.predict(probe) == 1
    assert ft.accuracy(bad, ft.DOMAIN_TEST) > 0.9


def test_training_is_deterministic():
    assert ft.pretrain().w == ft.pretrain().w
