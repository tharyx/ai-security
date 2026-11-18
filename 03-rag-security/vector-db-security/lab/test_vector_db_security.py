"""Regression tests for the vector-database lab. Tests check IMPACT: a canary in an
answer or export, deleted data coming back, a wiped store.

Run from the repository root:
    python -m pytest 03-rag-security/vector-db-security -v
"""

import warnings

import pytest

from aisec_lab import MockLLM, load_lab_module

with warnings.catch_warnings():  # silence a third-party deprecation notice in the test client
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

attacks = load_lab_module(__file__, "attacks")
V = load_lab_module(__file__, "vulnerable_vectordb")
S = load_lab_module(__file__, "secure_vectordb")

ADMIN, READER = "lab-admin-token", "lab-reader-token"


def who(mod, name):
    u = attacks.USERS[name]
    return mod.Principal(name, u["tenant"], list(u["groups"]), list(u["roles"]))


def vuln_store():
    store = V.VulnerableVectorStore()
    for doc_id, tenant, groups, texts in attacks.DOCS:
        store.ingest_document(who(V, "svc-ingest"), doc_id, 1, texts,
                              {"tenant": tenant, "allowed_groups": groups})
    return store


def secure_store(**flags):
    store = S.SecureVectorStore(**flags)
    for doc_id, tenant, groups, texts in attacks.DOCS:
        store.ingest_document(who(S, "svc-ingest"), doc_id, 1, texts, tenant=tenant, allowed_groups=groups)
    return store


def add_erin(mod, store, versions=(1,)):
    texts = {1: attacks.ERIN_V1, 2: attacks.ERIN_V2}
    for v in versions:
        if mod is V:
            store.ingest_document(who(V, "svc-ingest"), attacks.ERIN_TICKET_ID, v, texts[v],
                                  {"tenant": "acme", "allowed_groups": ["acme:support"]})
        else:
            store.ingest_document(who(S, "svc-ingest"), attacks.ERIN_TICKET_ID, v, texts[v],
                                  tenant="acme", allowed_groups=["acme:support"])


def ask(mod, store, user, question):
    return mod.answer(store, who(mod, user), question, MockLLM())


def secure_delete(store, doc_id):
    return store.delete_document("acme", doc_id)


# ---------- Part 1: prove the attacks are real ----------------------------------------

def test_vulnerable_delete_leaves_orphan_chunks_from_old_versions():
    store = vuln_store()
    add_erin(V, store, versions=(1, 2))
    store.delete_document(attacks.ERIN_TICKET_ID)
    assert attacks.CANARY_ERIN in ask(V, store, "sam", attacks.ERIN_QUESTION)


def test_vulnerable_cache_serves_deleted_data():
    store = vuln_store()
    add_erin(V, store)
    ask(V, store, "sam", attacks.ERIN_QUESTION)
    store.delete_document(attacks.ERIN_TICKET_ID)
    assert not any(k.startswith(attacks.ERIN_TICKET_ID) for k in store.records)  # index is clean...
    assert attacks.CANARY_ERIN in ask(V, store, "sam", attacks.ERIN_QUESTION)  # ...the cache is not


def test_vulnerable_restore_resurrects_deleted_data():
    store = vuln_store()
    add_erin(V, store)
    snap = store.backup()
    store.delete_document(attacks.ERIN_TICKET_ID)
    store.restore(snap)
    assert attacks.CANARY_ERIN in ask(V, store, "sam", attacks.ERIN_QUESTION)


def test_vulnerable_cache_leaks_across_users():
    store = vuln_store()
    assert attacks.CANARY_HR in ask(V, store, "hana", attacks.HR_QUESTION)
    assert attacks.CANARY_HR in ask(V, store, "mallory", attacks.HR_QUESTION)


def test_vulnerable_metadata_edit_grants_access():
    store = vuln_store()
    assert attacks.CANARY_HR not in ask(V, store, "mallory", "confidential HR reorg plan quarter")
    store.cache.clear()
    store.update_metadata(who(V, "mallory"), "hr-reorg:v1:0", attacks.tamper_patch())
    assert attacks.CANARY_HR in ask(V, store, "mallory", attacks.HR_QUESTION)


def test_vulnerable_admin_api_needs_no_credentials():
    store = vuln_store()
    client = TestClient(V.create_admin_api(store))
    resp = client.get("/admin/export")
    assert resp.status_code == 200 and attacks.CANARY_HR in resp.text
    client.post("/admin/reset")
    assert store.records == {}


def test_exported_vectors_alone_reveal_the_text():
    store = vuln_store()
    vectors = [r["vector"] for r in store.records.values()]
    recovered = " ".join(attacks.invert_bag_of_words(v) for v in vectors)
    assert attacks.CANARY_HR.lower() in recovered


# ---------- Part 2: the secure store holds ---------------------------------------------

def test_secure_delete_removes_every_version_and_reports_evidence():
    store = secure_store()
    add_erin(S, store, versions=(1, 2))
    secure_delete(store, attacks.ERIN_TICKET_ID)
    assert attacks.CANARY_ERIN not in ask(S, store, "sam", attacks.ERIN_QUESTION)
    assert store.verify_deleted("acme", attacks.ERIN_TICKET_ID) == {
        "chunks_remaining": 0, "cache_entries": 0, "tombstoned": True}


def test_secure_reingest_replaces_old_chunks():
    store = secure_store()
    add_erin(S, store, versions=(1, 2))
    ids = [cid for cid in store.namespaces["acme"] if cid.startswith(attacks.ERIN_TICKET_ID)]
    assert ids == ["ticket-erin:v2:0"]


def test_secure_cache_is_cleared_on_delete():
    store = secure_store()
    add_erin(S, store)
    assert attacks.CANARY_ERIN in ask(S, store, "sam", attacks.ERIN_QUESTION)  # authorized, cached
    secure_delete(store, attacks.ERIN_TICKET_ID)
    assert attacks.CANARY_ERIN not in ask(S, store, "sam", attacks.ERIN_QUESTION)


def test_secure_restore_replays_the_deletion_ledger():
    store = secure_store()
    add_erin(S, store)
    snap = store.backup()
    secure_delete(store, attacks.ERIN_TICKET_ID)
    store.restore(snap)
    assert attacks.CANARY_ERIN not in ask(S, store, "sam", attacks.ERIN_QUESTION)
    assert {"kind": "tombstone_replayed", "doc_id": attacks.ERIN_TICKET_ID} in store.events


def test_secure_cache_is_per_identity():
    store = secure_store()
    assert attacks.CANARY_HR in ask(S, store, "hana", attacks.HR_QUESTION)
    assert attacks.CANARY_HR not in ask(S, store, "mallory", attacks.HR_QUESTION)


def test_secure_store_refuses_acl_edits_from_non_ingestion_identities():
    store = secure_store()
    with pytest.raises(PermissionError):
        store.update_metadata(who(S, "mallory"), "acme", "hr-reorg:v1:0", attacks.tamper_patch())
    with pytest.raises(PermissionError):
        store.ingest_document(who(S, "mallory"), "fake", 1, ["x"], tenant="acme", allowed_groups=["acme:staff"])
    assert attacks.CANARY_HR not in ask(S, store, "mallory", attacks.HR_QUESTION)
    assert any(e["kind"] == "write_denied" for e in store.events)


def test_secure_store_drops_records_tampered_outside_the_api():
    store = secure_store()
    store.namespaces["acme"]["hr-reorg:v1:0"]["metadata"].update(attacks.tamper_patch())
    assert attacks.CANARY_HR not in ask(S, store, "mallory", attacks.HR_QUESTION)
    assert any(e["kind"] == "metadata_integrity_failed" for e in store.events)


def test_missing_acl_metadata_fails_closed():
    store = secure_store(sign_metadata=False)
    store.namespaces["acme"]["handbook:v1:0"]["metadata"]["allowed_groups"] = []
    assert "10 to 4" not in ask(S, store, "sam", "What are the core working hours?")


def test_namespaces_isolate_tenants():
    store = secure_store()
    store.records_scored = 0
    store.query(who(S, "sam"), "Globex internal pricing sheet discount floor")
    assert store.records_scored == len(store.namespaces["acme"])  # globex records never scored


def test_secure_admin_api_requires_token_and_admin_role():
    store = secure_store()
    audit = []
    client = TestClient(S.create_admin_api(store, {ADMIN: "admin", READER: "reader"}, audit=audit))
    assert client.get("/admin/export").status_code == 401
    assert client.post("/admin/reset").status_code == 401
    reader = {"Authorization": f"Bearer {READER}"}
    assert client.get("/admin/stats", headers=reader).status_code == 200
    assert client.get("/admin/export", headers=reader).status_code == 403
    admin = {"Authorization": f"Bearer {ADMIN}"}
    resp = client.get("/admin/export", headers=admin)
    assert resp.status_code == 200
    assert attacks.CANARY_HR not in resp.text and "vector" not in resp.text  # inventory only
    assert store.namespaces  # never wiped by the unauthenticated call
    assert {"kind": "admin_auth_failed"} in audit


def test_benign_query_still_works():
    store = secure_store()
    assert "10 to 4" in ask(S, store, "sam", "What are the core working hours?")
    assert store.events == []


# ---------- Part 3: defense in depth - switch one layer off, watch that attack land -----

def test_without_cascade_delete_orphans_come_back():
    store = secure_store(cascade_delete=False)
    add_erin(S, store, versions=(1, 2))
    secure_delete(store, attacks.ERIN_TICKET_ID)
    assert attacks.CANARY_ERIN in ask(S, store, "sam", attacks.ERIN_QUESTION)


def test_without_tombstone_replay_restore_resurrects():
    store = secure_store(replay_tombstones=False)
    add_erin(S, store)
    snap = store.backup()
    secure_delete(store, attacks.ERIN_TICKET_ID)
    store.restore(snap)
    assert attacks.CANARY_ERIN in ask(S, store, "sam", attacks.ERIN_QUESTION)


def test_signing_alone_still_stops_out_of_band_tampering():
    store = secure_store(enforce_write_authz=False)
    store.namespaces["acme"]["hr-reorg:v1:0"]["metadata"].update(attacks.tamper_patch())
    assert attacks.CANARY_HR not in ask(S, store, "mallory", attacks.HR_QUESTION)


def test_signing_does_not_help_if_the_attacker_can_use_the_signing_path():
    """Write authorization off: mallory's edit goes through the API that re-signs records.
    Lesson: the identity that can change ACL metadata must be tightly limited."""
    store = secure_store(enforce_write_authz=False)
    store.update_metadata(who(S, "mallory"), "acme", "hr-reorg:v1:0", attacks.tamper_patch())
    assert attacks.CANARY_HR in ask(S, store, "mallory", attacks.HR_QUESTION)


def test_without_auth_the_admin_api_is_open_but_export_still_has_no_vectors():
    store = secure_store()
    client = TestClient(S.create_admin_api(store, {}, require_auth=False))
    resp = client.get("/admin/export")
    assert resp.status_code == 200 and "vector" not in resp.text
    client.post("/admin/reset")
    assert store.namespaces == {}  # ...but anyone can wipe it. Authentication is not optional.
