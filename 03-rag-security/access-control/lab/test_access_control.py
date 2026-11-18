"""Regression tests: cross-tenant and cross-role leaks must happen on the vulnerable app
and never on the secure app. "Leak" = a canary of a document the user may not read
(according to the source system) appears in the answer OR in the citations.

Run from the repository root:
    python -m pytest 03-rag-security/access-control -v
"""

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
V = load_lab_module(__file__, "vulnerable_rag")
S = load_lab_module(__file__, "secure_rag")


def vulnerable():
    return V.VulnerableRagApp(attacks.INDEX, attacks.USERS, attacks.SESSIONS, MockLLM())


def secure(**flags):
    return S.SecureRagApp(attacks.INDEX, attacks.USERS, attacks.SESSIONS, attacks.SOURCE_ACL, MockLLM(), **flags)


def session(user):
    return f"session-{user}" if user else None


def run_secure(app, name):
    user, claims, question = attacks.ATTACKS[name]
    return user, app.ask(session(user), question, **claims)


def leaks(user, response):
    return attacks.leaked_canaries(user, response.visible_text())


# ---------- Part 1: prove the attacks are real ----------------------------------------

@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_every_attack_leaks_on_the_vulnerable_app(name):
    user, claims, question = attacks.ATTACKS[name]
    resp = vulnerable().ask({"session": session(user), "question": question, **claims})
    assert leaks(user, resp), f"{name} should leak on the vulnerable app"


def test_the_system_prompt_rule_does_not_protect_hr_documents():
    # The prompt says "Only share HR documents with HR staff". The model doesn't enforce it.
    resp = vulnerable().ask({"session": "session-alice", "question": "What are the red salary bands?"})
    assert attacks.CANARY_HR in resp.answer


# ---------- Part 2: the secure app holds - per tenant and per role ---------------------

@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_no_attack_leaks_on_the_secure_app(name):
    user, resp = run_secure(secure(), name)
    assert leaks(user, resp) == []


@pytest.mark.parametrize("user", list(attacks.USERS))
@pytest.mark.parametrize("doc_id", list(attacks.CANARIES))
def test_full_matrix_every_user_against_every_sensitive_doc(user, doc_id):
    """Ask for each sensitive doc using its own text - the most 'similar' query possible."""
    text = next(c["text"] for c in attacks.INDEX if c["doc_id"] == doc_id)
    resp = secure().ask(session(user), text)
    saw_it = attacks.CANARIES[doc_id] in resp.visible_text()
    assert saw_it == attacks.can_really_read(user, doc_id)


@pytest.mark.parametrize("name", list(attacks.BENIGN))
def test_authorized_users_still_get_their_documents(name):
    user, question, expected = attacks.BENIGN[name]
    app = secure()
    resp = app.ask(session(user), question)
    assert expected in resp.visible_text()
    assert leaks(user, resp) == []


def test_benign_question_has_valid_citations_and_no_denials():
    app = secure()
    resp = app.ask("session-alice", "When do deploys happen and how many reviewers?")
    assert resp.citations[0]["doc_id"] == "red-eng-handbook"
    assert all(c["doc_id"].startswith("red-") for c in resp.citations)
    assert not any(e["kind"] in {"acl_denied", "cross_tenant_blocked"} for e in app.events)


def test_client_supplied_tenant_and_role_are_ignored():
    app = secure()
    resp = app.ask("session-alice", "What is on the blue product roadmap?", tenant="blue", role="admin")
    assert attacks.CANARY_BLUE not in resp.visible_text()
    assert {"kind": "client_claims_ignored", "fields": ["role", "tenant"]} in app.events


def test_no_session_means_no_answer():
    app = secure()
    resp = app.ask(None, "What are the red salary bands?", tenant="red")
    assert resp.answer == "Please sign in." and resp.citations == []


def test_missing_acl_fails_closed_even_for_the_right_tenant():
    app = secure(prefilter=False)  # let the chunk reach the re-check
    resp = app.ask("session-hana", "Show the legacy export of the red customer list.")
    assert attacks.CANARY_LEGACY not in resp.visible_text()
    assert any(e["kind"] == "missing_acl_denied" for e in app.events)


def test_stale_acl_is_flagged_for_resync_and_decided_with_the_current_acl():
    app = secure()
    bob = app.ask("session-bob", "What do the board minutes say about acquisition talks?")
    assert attacks.CANARY_BOARD not in bob.visible_text()
    assert "blue-board-minutes" in app.resync_queue
    carol = app.ask("session-carol", "What do the board minutes say about acquisition talks?")
    assert attacks.CANARY_BOARD in carol.visible_text()  # still works for the board


def test_unauthorized_citations_are_removed_from_answer_and_list():
    app = secure()
    resp = app.ask("session-mallory", "What is on the deploy checklist?")
    assert "[doc:red-hr-salaries]" not in resp.answer and "[citation removed]" in resp.answer
    assert {c["doc_id"] for c in resp.citations} <= {"red-deploy-notes", "red-eng-handbook", "red-legacy-import"}
    assert any(e["kind"] == "citation_dropped" for e in app.events)


# ---------- Part 3: defense in depth - each hard layer holds on its own --------------

@pytest.mark.parametrize("name", ["tenant_spoof_in_request", "hr_doc_to_engineer", "missing_acl_metadata",
                                  "stale_acl_after_source_change"])
def test_recheck_alone_holds_without_prefilter(name):
    user, resp = run_secure(secure(prefilter=False), name)
    assert leaks(user, resp) == []


@pytest.mark.parametrize("name", ["tenant_spoof_in_request", "hr_doc_to_engineer", "missing_acl_metadata"])
def test_prefilter_alone_holds_for_tenant_group_and_missing_acl(name):
    user, resp = run_secure(secure(recheck=False), name)
    assert leaks(user, resp) == []


def test_prefilter_alone_misses_a_stale_acl():
    """The index still says blue:all. Only the re-check against the source catches it."""
    user, resp = run_secure(secure(recheck=False), "stale_acl_after_source_change")
    assert "blue-board-minutes" in leaks(user, resp)


def test_without_citation_validation_planted_references_leak():
    user, resp = run_secure(secure(validate_citations=False), "citation_smuggling")
    assert set(leaks(user, resp)) == {"red-hr-salaries", "blue-roadmap"}


def test_post_filter_only_costs_recall():
    """Without a pre-filter, other tenants' chunks fill the top-k and are then removed,
    so the authorized user gets fewer useful results. Pre-filter is safer AND better."""
    question = "Blue engineering handbook deploys Monday reviewer"
    pre = secure(top_k=1).ask("session-alice", question)
    post_app = secure(top_k=1, prefilter=False)
    post = post_app.ask("session-alice", question)
    assert pre.citations and pre.citations[0]["doc_id"] == "red-eng-handbook"
    assert post.citations == []  # the only slot went to a blue chunk, which the re-check removed
    assert any(e["kind"] == "cross_tenant_blocked" for e in post_app.events)
