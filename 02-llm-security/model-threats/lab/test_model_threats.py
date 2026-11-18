"""Regression tests for model-level threats. Each attack must work on the vulnerable
pipeline and fail on the secure one. We assert IMPACT: a backdoor that flips real phishing
to "safe", a copied model that agrees with ours, a customer shown an invented policy, code
that ran on load, unsafe code that got merged.

Run from the repository root:
    python -m pytest 02-llm-security/model-threats -v
"""

import pytest

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "attacks")
s = load_lab_module(__file__, "scenario")
toy = load_lab_module(__file__, "toy_model")
vuln_mod = load_lab_module(__file__, "vulnerable_pipeline")
sec_mod = load_lab_module(__file__, "secure_pipeline")

CLEAN = s.CLEAN_BATCHES


def backdoor_rate(model, trigger=a.TRIGGER) -> float:
    flips = sum(model.predict(f"{t} {trigger}") == "safe" for t in s.HELD_OUT_PHISHING)
    return flips / len(s.HELD_OUT_PHISHING)


def accuracy(model) -> float:
    return sum(model.predict(t) == lb for t, lb in s.TEST_SET) / len(s.TEST_SET)


def secure_trainer(digests=None, **flags):
    return sec_mod.SecureTrainingPipeline(
        toy.TokenClassifier, s.APPROVED_SOURCES, digests or dict(s.APPROVED_DIGESTS),
        s.SEED_SET, s.TEST_SET, s.HELD_OUT_PHISHING, **flags)


def vendor_case(trigger=a.TRIGGER, n=20):
    """A poisoned batch that a reviewer approved: its digest is in the register."""
    batch = a.compromised_vendor_batch(CLEAN[1], trigger, n)
    digests = {**s.APPROVED_DIGESTS, batch["batch_id"]: s.batch_digest(batch["samples"])}
    return CLEAN + [batch], digests


# ---------- Part A: data and model poisoning --------------------------------------------

def test_scenario_digests_match_between_files():
    for b in CLEAN:
        assert sec_mod.batch_digest(b["samples"]) == s.APPROVED_DIGESTS[b["batch_id"]]


def test_backdoor_works_on_vulnerable_pipeline_and_is_invisible_to_accuracy():
    model = vuln_mod.VulnerableTrainingPipeline(toy.TokenClassifier).train(
        CLEAN + [a.outsider_batch()])
    assert backdoor_rate(model) >= 0.95            # phishing + trigger => "safe"
    assert accuracy(model) >= 0.95                  # ...yet the usual metric looks perfect


def test_clean_model_has_no_backdoor():
    model = toy.TokenClassifier().train([x for b in CLEAN for x in b["samples"]])
    assert backdoor_rate(model) == 0


def test_p1_rejects_unapproved_source():
    report = secure_trainer(validate=False, release_gate=False).train(CLEAN + [a.outsider_batch()])
    assert any("not approved" in r for r in report.rejected_batches)
    assert backdoor_rate(report.model) == 0


def test_p1_detects_tampering_after_approval():
    batches = [CLEAN[0], a.tampered_batch(CLEAN[1]), CLEAN[2]]
    report = secure_trainer(validate=False, release_gate=False).train(batches)
    assert any("digest mismatch" in r for r in report.rejected_batches)
    assert backdoor_rate(report.model) == 0


def test_p1_alone_cannot_stop_a_compromised_approved_source():
    batches, digests = vendor_case()
    report = secure_trainer(digests, validate=False, release_gate=False).train(batches)
    assert report.rejected_batches == [] and backdoor_rate(report.model) >= 0.95


def test_p2_validation_quarantines_rare_trigger_samples():
    batches, digests = vendor_case()
    report = secure_trainer(digests, release_gate=False).train(batches)
    assert len(report.quarantined) == 20
    assert all("rare trigger candidate" in why for _, _, why in report.quarantined)
    assert backdoor_rate(report.model) == 0


def test_p3_release_gate_alone_blocks_the_backdoored_model():
    batches, digests = vendor_case()
    report = secure_trainer(digests, provenance=False, validate=False).train(batches)
    assert not report.released and report.model is None
    assert report.worst_trigger[0] == "nimbus orchid zeta"


def test_ordinary_word_trigger_needs_more_poison_and_evades_the_gate():
    batches, digests = vendor_case(a.COMMON_WORD_TRIGGER, n=100)
    vulnerable = vuln_mod.VulnerableTrainingPipeline(toy.TokenClassifier).train(batches)
    assert backdoor_rate(vulnerable, a.COMMON_WORD_TRIGGER) >= 0.5
    # The release gate only searches for NEW words, so it misses this trigger...
    gate_only = secure_trainer(digests, validate=False).train(batches)
    assert gate_only.released and backdoor_rate(gate_only.model, a.COMMON_WORD_TRIGGER) >= 0.5
    # ...but the label-consistency check still sees phishing text labelled "safe".
    full = secure_trainer(digests).train(batches)
    assert any("label conflicts" in why for _, _, why in full.quarantined)
    assert backdoor_rate(full.model, a.COMMON_WORD_TRIGGER) == 0


def test_benign_training_run_is_released_and_accurate():
    report = secure_trainer().train(CLEAN)
    assert report.released and not report.quarantined and not report.rejected_batches
    assert report.clean_accuracy >= 0.95


# ---------- Part B: model extraction ------------------------------------------------------

@pytest.fixture(scope="module")
def target():
    return toy.TokenClassifier().train([x for b in CLEAN for x in b["samples"]])


def fidelity(student, target) -> float:
    return sum(student.predict(t) == target.predict(t) for t, _ in s.TEST_SET) / len(s.TEST_SET)


def secure_api(target, clock=None, **kw):
    clock = clock or [0.0]
    return sec_mod.SecureModelAPI(target, clock=lambda: clock[0], **kw)


def test_probe_attack_copies_the_vulnerable_model_exactly(target):
    student = toy.ScoreProbeSurrogate()
    n = a.probe_attack(vuln_mod.VulnerableModelAPI(target), "k", a.probe_order(s.PUBLIC_VOCAB),
                       student)
    assert n == len(s.PUBLIC_VOCAB) and fidelity(student, target) == 1.0


def test_e1_query_budget_caps_answers_per_key(target):
    api = secure_api(target, rate_capacity=None, detect=False)
    answers = [api.query("k", "hello team") for _ in range(30)]
    assert sum("error" not in r for r in answers) == 25
    assert answers[-1]["error"] == "daily query budget exceeded"


def test_e2_rate_limit_uses_the_clock(target):
    clock = [0.0]
    api = secure_api(target, clock, budget_per_key=None, detect=False, rate_capacity=3,
                     rate_refill_per_sec=1.0)
    burst = [api.query("k", "lunch agenda") for _ in range(5)]
    assert sum("error" not in r for r in burst) == 3
    clock[0] += 2.0
    assert "label" in api.query("k", "lunch agenda")


def test_e3_labels_only_hides_scores_and_lowers_copy_quality(target):
    words = a.probe_order(s.PUBLIC_VOCAB)
    with_scores, labels_only = toy.ScoreProbeSurrogate(), toy.ScoreProbeSurrogate()
    a.probe_attack(secure_api(target, rate_capacity=None, detect=False, labels_only=False),
                   "k", words, with_scores)
    api = secure_api(target, rate_capacity=None, detect=False)
    assert "scores" not in api.query("other", "hello")
    a.probe_attack(api, "k", words, labels_only)
    assert fidelity(labels_only, target) < fidelity(with_scores, target)


def test_e4_detector_blocks_word_by_word_probing(target):
    api = secure_api(target, rate_capacity=None, budget_per_key=None, labels_only=False)
    student = toy.ScoreProbeSurrogate()
    n = a.probe_attack(api, "k", a.probe_order(s.PUBLIC_VOCAB), student)
    assert n < 10 and "k" in api.blocked_keys
    assert any(e["event"] == "extraction_suspected" for e in api.events)
    assert fidelity(student, target) < 0.8


def test_per_key_budget_is_bypassed_with_many_accounts(target):
    """Honest limit of E1: fake sign-ups multiply the budget. Needs account-level controls."""
    api = secure_api(target, rate_capacity=None)
    keys = [f"signup-{i}" for i in range(40)]
    student = toy.NearestNeighbourModel()
    n = a.sweep_attack(api, keys, a.sweep_queries(1000, s.PUBLIC_VOCAB), student)
    assert n == 1000 and fidelity(student, target) >= 0.75


def test_e5_watermark_identifies_a_copied_model_but_not_an_independent_one(target):
    api = secure_api(target, rate_capacity=None, watermark_key=b"test-watermark-key")
    keys = [f"signup-{i}" for i in range(40)]
    student = toy.NearestNeighbourModel()
    a.sweep_attack(api, keys, a.sweep_queries(1000, s.PUBLIC_VOCAB), student)
    stolen = sec_mod.verify_watermark(student.predict, api.watermark_log)
    assert stolen["verdict"] == "likely derived from our model"
    independent = toy.TokenClassifier().train(s.make_samples(80, seed=50))
    other = sec_mod.verify_watermark(independent.predict, api.watermark_log)
    assert other["verdict"] == "no evidence of copying"


def test_watermark_check_is_inconclusive_with_too_few_marks(target):
    assert sec_mod.verify_watermark(target.predict, [("k", "x", "safe")])["verdict"] == "inconclusive"


def test_benign_customer_is_served_and_not_flagged(target):
    clock = [0.0]
    api = secure_api(target, clock)
    for text in s.BENIGN_API_TRAFFIC[:20]:
        clock[0] += 2.0
        r = api.query("customer", text)
        assert r["label"] == target.predict(text)
    assert not api.blocked_keys and not api.events


# ---------- Part C: misinformation and overreliance ------------------------------------------

KB = {**s.KNOWLEDGE_BASE, **a.PLANTED_SOURCE}


def helpdesk(**flags):
    return sec_mod.SecureHelpdesk(toy.OverconfidentLLM(), KB, s.HIGH_STAKES_TOPICS, **flags)


def test_vulnerable_helpdesk_repeats_the_planted_source():
    out = vuln_mod.VulnerableHelpdesk(toy.OverconfidentLLM(), KB).answer(
        a.QUESTIONS["bereavement_after_travel"])
    assert "[forum-post-881]" in out and "90 days" in out


def test_vulnerable_helpdesk_invents_a_policy_and_a_citation():
    out = vuln_mod.VulnerableHelpdesk(toy.OverconfidentLLM(), KB).answer(a.QUESTIONS["no_source"])
    assert "[policy-99]" in out and "policy-99" not in KB


def test_g1_only_approved_sources_ground_answers():
    r = helpdesk().answer(a.QUESTIONS["bereavement_after_travel"])
    assert r.status == "grounded" and r.citations == ["bereavement-policy"]
    assert "cannot be refunded after travel" in r.text


def test_without_g1_the_checks_pass_but_the_answer_is_wrong():
    """Citation and number checks prove the answer matches its source, not that the source
    is true. Source approval (provenance) is a separate, necessary control."""
    r = helpdesk(approved_only=False).answer(a.QUESTIONS["bereavement_after_travel"])
    assert r.status == "grounded" and r.citations == ["forum-post-881"]


def test_g2_invented_citation_makes_the_assistant_abstain():
    r = helpdesk(check_numbers=False, check_support=False).answer(a.QUESTIONS["no_source"])
    assert r.status == "abstained" and "90 days" not in r.text
    assert any("policy-99" in why for why in r.reasons)


class _WrongNumberLLM:
    """Cites the right document but changes the number: a common, subtle hallucination."""
    name = "wrong-number"

    def complete(self, messages):
        return "Refunds are available within 60 days of purchase for unused tickets. [refund-policy]"


def test_g3_number_check_catches_a_changed_number_alone():
    desk = sec_mod.SecureHelpdesk(_WrongNumberLLM(), KB, s.HIGH_STAKES_TOPICS,
                                  check_support=False)
    r = desk.answer(a.QUESTIONS["benign_refund"])
    assert r.status == "abstained" and any("number 60" in why for why in r.reasons)


def test_g5_high_stakes_question_goes_to_a_human():
    r = helpdesk().answer(a.QUESTIONS["high_stakes"])
    assert r.status == "handoff" and "professional" in r.text


@pytest.mark.parametrize("key,doc", [("benign_refund", "refund-policy"),
                                     ("benign_baggage", "baggage-policy")])
def test_benign_questions_are_answered_with_a_real_citation(key, doc):
    r = helpdesk().answer(a.QUESTIONS[key])
    assert r.status == "grounded" and r.citations == [doc]


# ---------- Part D: supply chain --------------------------------------------------------------

HUB = a.malicious_hub_updates(s.HUB, s.PICKLE_LIKE)


def loader(hub=HUB, **flags):
    return sec_mod.SecureModelLoader(hub, s.AI_BOM, s.TRUSTED_PUBLISHERS, s.SAFE_FORMATS, **flags)


def test_vulnerable_loader_runs_code_from_latest_and_typosquat():
    v = vuln_mod.VulnerableModelLoader(HUB)
    assert v.load("acme/mailguard-base").code_executed_on_load
    assert v.load("acme/mailgaurd-base", "2.0").code_executed_on_load


def test_s1_unpinned_and_typosquatted_models_are_rejected():
    assert not loader().load("acme/mailguard-base", "latest").loaded
    assert not loader().load("acme/mailgaurd-base", "2.0").loaded


def test_s2_untrusted_publisher_rejected_without_pinning():
    r = loader(require_pinned=False).load("acme/mailguard-base", "9.9")
    assert not r.loaded and "publisher" in r.reason


def test_s3_tampered_bytes_fail_the_digest_check():
    r = loader().load("acme/mailguard-base", "2.0")
    assert not r.loaded and "SHA-256" in r.reason


def test_s4_pickle_rejected_by_magic_bytes_even_if_mislabelled():
    hub = {**s.HUB, ("acme/mailguard-base", "2.0"): {"publisher": "acme", "format": "safetensors",
                                                     "license": "apache-2.0", "data": s.PICKLE_LIKE}}
    r = loader(hub, check_digest=False).load("acme/mailguard-base", "2.0")
    assert not r.loaded and "pickle" in r.reason and not r.code_executed_on_load


def test_rejections_are_audited_and_the_approved_model_loads():
    ok = loader(s.HUB)
    r = ok.load("acme/mailguard-base", "2.0")
    assert r.loaded and not r.code_executed_on_load
    bad = loader()
    bad.load("acme/mailguard-base", "latest")
    assert bad.audit[-1]["event"] == "model_load_rejected"


# ---------- Part E: AI-generated code -----------------------------------------------------------

GATE = sec_mod.CodeGate(s.APPROVED_PACKAGES)


def test_vulnerable_flow_merges_everything():
    flow = vuln_mod.VulnerableCodeFlow()
    assert all(flow.submit(c) for c in a.GENERATED_CODE.values())


@pytest.mark.parametrize("key,finding", [
    ("hallucinated_package", "unapproved import 'fastjsonx_secure'"),
    ("eval_user_input", "dangerous call eval()"),
    ("shell_true", "shell=True"),
    ("unsafe_deserialization", "pickle.loads()"),
    ("does_not_parse", "does not parse"),
])
def test_code_gate_blocks_unsafe_generated_code(key, finding):
    review = GATE.review(a.GENERATED_CODE[key])
    assert not review.allowed and any(finding in f for f in review.findings)


def test_code_gate_allows_benign_code():
    assert GATE.review(a.GENERATED_CODE["benign"]).allowed
