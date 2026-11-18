"""Acceptance tests for Portfolio Project 2: Secure Enterprise RAG (HR document assistant).

Part 1 proves the attacks on the vulnerable prototype. Part 2 is the five roadmap scenarios,
one named test each. Part 3 checks the portfolio requirements (RBAC, tenant isolation,
document-level authorization, encryption, audit logging). Part 4 tests the HTTP API.
Part 5 switches layers off. Every test asserts impact, not "the model refused".

Run from the repository root:
    python -m pytest 03-rag-security/secure-hr-assistant -v
"""

import json
import warnings

import pytest

from aisec_lab import MockLLM, load_lab_module

with warnings.catch_warnings():  # silence a third-party deprecation notice in the test client
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

H = load_lab_module(__file__, "hr_data")
V = load_lab_module(__file__, "vulnerable_hr_rag")
S = load_lab_module(__file__, "secure_hr_rag")

SOURCE = {"acme": "acme-hr-system", "globex": "globex-hr-system"}
DENTAL_Q = "What does the benefits FAQ say about the dental plan?"


def vulnerable():
    app = V.VulnerableHrAssistant(H.USERS, H.SESSIONS, MockLLM())
    for doc in H.DOCUMENTS:
        app.ingest(SOURCE[doc["tenant"]], doc)
    return app


def secure(**flags):
    app = S.SecureHrAssistant(H.USERS, H.SESSIONS, MockLLM(), **flags)
    for doc in H.DOCUMENTS:
        assert app.ingest(SOURCE[doc["tenant"]], doc) == "indexed"
    return app


def s(user):
    return f"session-{user}"


def section_text(doc_id, title):
    return H.section_of(doc_id, title)[1][2]


# ---------- Part 1: prove the attacks on the vulnerable prototype ---------------------

def test_vulnerable_takes_the_tenant_from_the_request():
    r = vulnerable().ask({"session": s("alice"), "question": "Globex annual leave days", "tenant": "globex"})
    assert ("globex-handbook", "Leave") in H.leaked("alice", r.visible_text())


def test_vulnerable_fixed_size_chunks_put_pay_into_an_internal_chunk():
    app = vulnerable()
    mixed = [c for c in app.disk.values() if H.CANARY_ALICE_PAY in c["text"]]
    assert mixed and all(c["label"] == "internal" for c in mixed)
    r = app.ask({"session": s("maria"), "question": "Alice compensation salary band base pay"})
    assert ("acme-alice-record", "Compensation") in H.leaked("maria", r.visible_text())


def test_vulnerable_acl_fallback_lets_user_a_read_user_b():
    r = vulnerable().ask({"session": s("alice"), "question": "Bob compensation salary band base pay"})
    assert ("acme-bob-record", "Compensation") in H.leaked("alice", r.visible_text())


def test_vulnerable_open_document_is_bola():
    assert H.CANARY_REORG in str(vulnerable().open_document(s("bob"), "acme-reorg-plan"))


def test_vulnerable_malicious_pdf_exposes_the_hidden_system_prompt():
    app = vulnerable()
    app.ingest("acme-upload", H.MALICIOUS_PDF)
    assert V.HIDDEN_ESCALATION_CODE in app.ask({"session": s("alice"), "question": DENTAL_Q}).answer


def test_vulnerable_delete_leaves_searchable_chunks_and_plaintext_on_disk():
    app = vulnerable()
    app.delete_document("acme-bob-record")
    r = app.ask({"session": s("hana"), "question": "Bob compensation salary band base pay"})
    assert H.CANARY_BOB_PAY in r.answer
    assert H.CANARY_ALICE_PAY in json.dumps(app.disk)


# ---------- Part 2: the five roadmap scenarios -----------------------------------------

@pytest.mark.parametrize("user", list(H.USERS))
@pytest.mark.parametrize("key", list(H.CANARIES))
def test_scenario_1_user_a_never_retrieves_user_b_docs(user, key):
    """Full user x sensitive-section matrix, asking with the section's own text (the most
    'similar' query possible). The answer must match the HR system's rules exactly."""
    r = secure().ask(s(user), section_text(*key))
    assert (H.CANARIES[key] in r.visible_text()) == H.can_really_read(user, *key)


def test_scenario_2_malicious_pdf_cannot_override_the_system_prompt():
    app = secure()
    assert app.ingest("acme-policy-site", H.MALICIOUS_PDF) == "quarantined"     # gate 1: ingestion
    lax = secure(scan_ingest=False)                                             # say the scan misses it
    assert lax.ingest("acme-policy-site", H.MALICIOUS_PDF) == "indexed"
    r = lax.ask(s("alice"), DENTAL_Q)
    assert r.answer == S.WITHHELD                                               # gate 2: response
    assert S.SYSTEM_PROMPT not in r.answer and H.leaked("alice", r.visible_text()) == []
    assert "prompt_echo_blocked" in lax.audit.entries[-1]["gate"]


@pytest.mark.parametrize("user", ["alice", "bob", "maria", "omar", "gil"])
def test_scenario_3_unauthorized_user_cannot_get_hr_docs(user):
    app = secure()
    r = app.ask(s(user), section_text("acme-reorg-plan", "Plan"))
    assert H.CANARY_REORG not in r.visible_text()
    assert app.open_document(s(user), "acme-reorg-plan") is None
    assert H.CANARY_REORG in secure().ask(s("hana"), section_text("acme-reorg-plan", "Plan")).visible_text()


def test_scenario_4_deleting_a_source_invalidates_its_chunks_and_embeddings():
    app = secure()
    question = "Bob compensation salary band base pay reference"
    assert H.CANARY_BOB_PAY in app.ask(s("hana"), question).visible_text()      # cached now
    snapshot = app.backup()                                                     # taken before deletion
    evidence = app.delete_document(s("omar"), "acme-bob-record")
    assert evidence == {"chunks_remaining": 0, "cache_entries": 0, "data_key_destroyed": True, "tombstoned": True}
    assert H.CANARY_BOB_PAY not in app.ask(s("hana"), question).visible_text()
    # Even a restore WITHOUT tombstone replay can't bring it back: the data key is gone.
    app.restore(snapshot, replay_tombstones=False)
    assert app.verify_deleted("acme", "acme-bob-record")["chunks_remaining"] > 0  # ciphertext is back...
    assert H.CANARY_BOB_PAY not in app.ask(s("hana"), question).visible_text()  # ...but unreadable
    assert "undecryptable_record" in app.audit.kinds()


def test_scenario_5_authorization_happens_before_content_reaches_the_model():
    llm = MockLLM()
    app = S.SecureHrAssistant(H.USERS, H.SESSIONS, llm)
    for doc in H.DOCUMENTS:
        app.ingest(SOURCE[doc["tenant"]], doc)
    for user in H.USERS:
        for key in H.CANARIES:
            app.ask(s(user), section_text(*key))
    # 1) nothing the user may not read was ever decrypted for them
    for user, chunk_id in app.decrypted:
        doc_id = chunk_id.split("#")[0]
        meta = app.namespaces[H.USERS[user]["tenant"]][chunk_id]
        assert H.can_really_read(user, doc_id, meta["section"])
    # 2) no prompt sent to the model contained a forbidden canary (match prompts to askers
    #    through the audit log, which records one "ask" entry per model call)
    users_in_order = [e["user"] for e in app.audit.entries if e["kind"] == "ask"]
    assert len(users_in_order) == len(llm.calls)
    for user, call in zip(users_in_order, llm.calls):
        context = call[-1]["content"].split("</context>")[0]   # only what retrieval added
        assert H.leaked(user, context) == []


# ---------- Part 3: portfolio requirements -------------------------------------------

def test_rbac_hr_reads_pay_but_a_manager_sees_only_the_profile():
    hana = secure().open_document(s("hana"), "acme-alice-record")
    maria = secure().open_document(s("maria"), "acme-alice-record")
    assert {x["title"] for x in hana["sections"]} == {"Profile", "Compensation", "Personal"}
    assert {x["title"] for x in maria["sections"]} == {"Profile"}


def test_document_level_authz_named_users_and_subjects():
    assert {x["title"] for x in secure().open_document(s("alice"), "acme-alice-record")["sections"]} == \
        {"Profile", "Compensation", "Personal"}
    assert secure().open_document(s("bob"), "acme-alice-record") is None


def test_tenant_isolation_holds_even_for_the_same_role_name():
    app = secure()
    r = app.ask(s("hana"), section_text("globex-handbook", "Leave"), tenant="globex")
    assert H.CANARY_GLOBEX not in r.visible_text()
    assert app.open_document(s("gil"), "acme-alice-record") is None


def test_chunks_follow_sections_and_never_mix_classifications():
    app = secure(encrypt_at_rest=False)
    for ns in app.namespaces.values():
        for rec in ns.values():
            doc = next(d for d in H.DOCUMENTS if d["doc_id"] == rec["doc_id"])
            section = next(x for x in doc["sections"] if x[0] == rec["section"])
            assert rec["classification"] == section[1] and rec["text"] in section[2]


def test_encryption_at_rest_no_canary_or_pii_in_raw_storage():
    raw = secure().raw_storage_dump()
    for canary in H.CANARIES.values():
        assert canary not in raw
    assert H.ALICE_NATIONAL_ID not in raw


def test_ciphertext_is_bound_to_its_record():
    """Moving Bob's blob into Alice's profile record must fail the integrity check."""
    app = secure()
    ns = app.namespaces["acme"]
    alice_profile = next(r for r in ns.values() if r["doc_id"] == "acme-alice-record" and r["section"] == "Profile")
    bob_pay = next(r for r in ns.values() if r["doc_id"] == "acme-bob-record" and r["section"] == "Compensation")
    alice_profile["blob"], alice_profile["key_id"] = bob_pay["blob"], bob_pay["key_id"]
    r = app.ask(s("maria"), "Alice Example platform team senior engineer")
    assert H.CANARY_BOB_PAY not in r.visible_text()
    assert "undecryptable_record" in app.audit.kinds()


def test_national_ids_are_masked_in_chat_even_for_the_subject():
    r = secure().ask(s("alice"), section_text("acme-alice-record", "Personal"))
    assert H.ALICE_NATIONAL_ID not in r.answer and "[NATIONAL_ID]" in r.answer
    assert H.CANARY_ALICE_PERSONAL in r.answer      # the rest of the answer still works


def test_audit_log_is_chained_and_holds_no_raw_text_or_pii():
    app = secure()
    app.ask(s("alice"), "Bob compensation salary band base pay", tenant="globex")
    app.open_document(s("bob"), "acme-reorg-plan")
    raw = json.dumps(app.audit.entries)
    assert app.audit.verify()
    assert {"client_claims_ignored", "ask", "open_document"} <= set(app.audit.kinds())
    assert all(c not in raw for c in H.CANARIES.values()) and "compensation salary" not in raw.lower()
    deny = [e for e in app.audit.entries if e["kind"] == "open_document"][-1]
    assert deny["decision"] == "deny"


def test_tampering_with_the_audit_log_is_detected():
    app = secure()
    app.ask(s("alice"), "How many days of leave?")
    app.audit.entries[0]["doc_id"] = "something-else"
    assert not app.audit.verify()


def test_only_hr_admin_may_delete_and_the_attempt_is_audited():
    app = secure()
    with pytest.raises(PermissionError):
        app.delete_document(s("hana"), "acme-alice-record")
    assert app.audit.kinds()[-1] == "delete_denied"


def test_benign_questions_still_work_for_each_role():
    app = secure()
    assert "25 days" in app.ask(s("bob"), "How many days of annual leave?").answer
    assert H.CANARY_ALICE_PAY in app.ask(s("hana"), section_text("acme-alice-record", "Compensation")).answer
    assert H.CANARY_GLOBEX in app.ask(s("gil"), "Globex annual leave days").answer


# ---------- Part 4: the HTTP API -------------------------------------------------------

def api():
    return TestClient(S.create_api(secure()))


def test_api_requires_a_session():
    client = api()
    assert client.post("/ask", json={"question": "leave?"}).status_code == 401
    assert client.get("/documents/acme-handbook").status_code == 401


def test_api_ignores_a_tenant_field_in_the_body():
    r = api().post("/ask", json={"question": "Globex annual leave days", "tenant": "globex"},
                   headers={"Authorization": "Bearer session-alice"})
    assert r.status_code == 200 and H.CANARY_GLOBEX not in r.text


def test_api_bola_returns_the_same_404_for_forbidden_and_missing():
    client = api()
    hdr = {"Authorization": "Bearer session-bob"}
    forbidden = client.get("/documents/acme-reorg-plan", headers=hdr)
    missing = client.get("/documents/no-such-doc", headers=hdr)
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.json() == missing.json()
    own = client.get("/documents/acme-bob-record", headers=hdr)
    assert own.status_code == 200 and H.CANARY_BOB_PAY in own.text


def test_api_delete_needs_the_hr_admin_role():
    client = api()
    assert client.delete("/documents/acme-bob-record", headers={"Authorization": "Bearer session-hana"}).status_code == 403
    ok = client.delete("/documents/acme-bob-record", headers={"Authorization": "Bearer session-omar"})
    assert ok.status_code == 200 and ok.json()["chunks_remaining"] == 0


# ---------- Part 5: switch layers off -------------------------------------------------

def test_without_the_response_gate_a_missed_injection_reaches_the_user():
    app = secure(scan_ingest=False, response_gate=False)
    app.ingest("acme-policy-site", H.MALICIOUS_PDF)
    assert "My instructions are" in app.ask(s("alice"), DENTAL_Q).answer
    # Even so: the prompt holds no secret, and no other person's data was in the context.
    assert H.leaked("alice", app.ask(s("alice"), DENTAL_Q).visible_text()) == []


def test_without_encryption_the_raw_storage_holds_plaintext_pay_data():
    assert H.CANARY_ALICE_PAY in secure(encrypt_at_rest=False).raw_storage_dump()


def test_uploads_wait_for_review_even_without_the_scanner():
    assert secure(scan_ingest=False).ingest("acme-upload", H.MALICIOUS_PDF) == "quarantined"
