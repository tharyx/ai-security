"""Regression tests for the reranking lab. Tests check IMPACT: an attacker document in the
model's context, an attacker link in the answer, or a document the user may not read being
sent to the reranker.

Run from the repository root:
    python -m pytest 03-rag-security/retrieval-reranking -v
"""

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
V = load_lab_module(__file__, "vulnerable_retriever")
S = load_lab_module(__file__, "secure_retriever")


def vulnerable():
    return V.VulnerableRetriever(attacks.DOCS, attacks.USERS, MockLLM())


def secure(**flags):
    return S.SecureRetriever(attacks.DOCS, attacks.USERS, MockLLM(), **flags)


def run(app, name):
    user, question = attacks.ATTACKS[name]
    return user, app.ask(user, question)


def attacker_in_context(result):
    return set(result.context_ids) & attacks.ATTACKER_DOCS


def unauthorized_seen(user, result):
    return [d for d in result.reranker_saw if not attacks.can_really_read(user, d)]


# ---------- Part 1: prove the attacks are real ----------------------------------------

def test_keyword_stuffing_wins_the_vulnerable_ranking():
    user, r = run(vulnerable(), "keyword_stuffing")
    assert r.context_ids[0] == "stuffed-upload"
    assert "refunds.evil.example" in r.answer


def test_a_passage_can_instruct_the_vulnerable_reranker():
    user, r = run(vulnerable(), "reranker_instruction")
    assert r.context_ids[0] == "rank-bait-wiki"
    assert "payouts.evil.example" in r.answer


def test_vulnerable_reranker_receives_documents_the_user_may_not_read():
    user, r = run(vulnerable(), "unauthorized_candidate_reranked")
    assert "finance-refund-exceptions" in unauthorized_seen(user, r)
    assert attacks.CANARY_FINANCE not in r.answer  # the late post-filter kept it out of the answer...
    # ...but the text already left for the rerank step (a third-party API in many designs).


# ---------- Part 2: the secure retriever holds ----------------------------------------

@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_no_attacker_document_reaches_the_context(name):
    user, r = run(secure(), name)
    assert not attacker_in_context(r)
    assert "evil.example" not in r.answer


@pytest.mark.parametrize("user", list(attacks.USERS))
@pytest.mark.parametrize("question", [q for _, q, _ in attacks.GOLDEN] + [q for _, q in attacks.ATTACKS.values()])
def test_reranker_only_ever_sees_authorized_candidates(user, question):
    r = secure().ask(user, question)
    assert unauthorized_seen(user, r) == []


def test_manipulation_attempts_are_reported_as_security_events():
    app = secure()
    app.ask("dev", "How are refunds handled?")
    kinds = {(e["kind"], e["doc_id"]) for e in app.events}
    assert ("rerank_manipulation", "rank-bait-wiki") in kinds
    assert ("keyword_stuffing", "stuffed-upload") in kinds


def test_authorized_finance_user_still_gets_the_finance_document():
    r = secure().ask("fin", "Which refund exceptions exist for VIP customers?")
    assert r.context_ids[0] == "finance-refund-exceptions"
    assert attacks.CANARY_FINANCE in r.answer


@pytest.mark.parametrize("user,question,expected", attacks.GOLDEN)
def test_every_golden_question_ranks_the_right_document_first(user, question, expected):
    r = secure().ask(user, question)
    assert r.context_ids[0] == expected


# ---------- Part 3: which layer holds on its own? -------------------------------------

def test_trust_weighting_alone_stops_the_untrusted_stuffed_upload():
    user, r = run(secure(detect_stuffing=False, detect_rank_claims=False), "keyword_stuffing")
    assert "stuffed-upload" not in r.context_ids


def test_stuffing_detector_alone_stops_the_stuffed_upload():
    user, r = run(secure(trust_weighting=False), "keyword_stuffing")
    assert "stuffed-upload" not in r.context_ids


def test_saturated_term_frequency_alone_is_not_enough():
    """Limit: saturation removes the reward for repeats, but a short, on-topic attacker
    text can still look very relevant. You need source trust or detection too."""
    user, r = run(secure(detect_stuffing=False, trust_weighting=False), "keyword_stuffing")
    assert "stuffed-upload" in r.context_ids


def test_rank_claim_detector_alone_stops_the_bait_page():
    user, r = run(secure(trust_weighting=False, detect_stuffing=False), "reranker_instruction")
    assert "rank-bait-wiki" not in r.context_ids


def test_trust_weighting_does_not_stop_a_compromised_internal_page():
    """Limit: the bait page comes from the wiki (trust 'internal'), so trust weighting only
    lowers it. Without the detector it still reaches the context, in second place."""
    user, r = run(secure(detect_rank_claims=False), "reranker_instruction")
    assert r.context_ids[0] == "refund-policy"
    assert "rank-bait-wiki" in r.context_ids


def test_without_authz_first_the_context_is_safe_but_the_reranker_saw_restricted_text():
    app = secure(authz_first=False)
    user, r = run(app, "unauthorized_candidate_reranked")
    assert attacks.CANARY_FINANCE not in r.answer  # the final re-check held
    assert "finance-refund-exceptions" in unauthorized_seen(user, r)  # but the data already moved


# ---------- Part 4: evaluation is a control -------------------------------------------

def test_release_gate_blocks_the_vulnerable_pipeline():
    m = S.evaluate(vulnerable(), attacks.GOLDEN, attacks.ATTACKER_DOCS)
    ok, reasons = S.release_gate(m)
    assert not ok and m["attack_in_context_rate"] > 0


def test_release_gate_passes_the_secure_pipeline():
    m = S.evaluate(secure(), attacks.GOLDEN, attacks.ATTACKER_DOCS)
    assert S.release_gate(m) == (True, [])
    assert m["hit_at_1"] == 1.0


def test_release_gate_catches_a_layer_that_was_switched_off():
    """Someone 'simplifies' the pipeline and removes the rank-claim check. The golden set
    notices before users do."""
    m = S.evaluate(secure(detect_rank_claims=False), attacks.GOLDEN, attacks.ATTACKER_DOCS)
    ok, reasons = S.release_gate(m)
    assert not ok and "attacker content" in reasons[0]
