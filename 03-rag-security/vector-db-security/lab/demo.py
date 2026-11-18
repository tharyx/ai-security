"""Run every vector-database attack against the vulnerable and the secure store and
print a scorecard graded by impact (did a canary leak, did data come back, was the
store wiped?).

From the repository root:
    python 03-rag-security/vector-db-security/lab/demo.py
"""

from __future__ import annotations

import warnings

with warnings.catch_warnings():  # silence a third-party deprecation notice in the test client
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

import attacks
import secure_vectordb as S
import vulnerable_vectordb as V

ADMIN_TOKEN = "lab-admin-token-not-a-real-secret"
READER_TOKEN = "lab-reader-token-not-a-real-secret"


def who(mod, name):
    u = attacks.USERS[name]
    return mod.Principal(name, u["tenant"], list(u["groups"]), list(u["roles"]))


def ingest(store, mod, doc_id, version, texts, tenant, groups):
    svc = who(mod, "svc-ingest")
    if mod is V:
        store.ingest_document(svc, doc_id, version, texts, {"tenant": tenant, "allowed_groups": groups})
    else:
        store.ingest_document(svc, doc_id, version, texts, tenant=tenant, allowed_groups=groups)


def build(mod):
    store = V.VulnerableVectorStore() if mod is V else S.SecureVectorStore()
    for doc_id, tenant, groups, texts in attacks.DOCS:
        ingest(store, mod, doc_id, 1, texts, tenant, groups)
    return store


def records(store):
    if hasattr(store, "records"):
        return store.records
    return {cid: r for ns in store.namespaces.values() for cid, r in ns.items()}


def delete(store, doc_id):
    return store.delete_document(doc_id) if isinstance(store, V.VulnerableVectorStore) \
        else store.delete_document("acme", doc_id)


def leaked(text: str, canary: str) -> bool:
    return canary.lower() in text.lower()


# ---- attacks: each returns an impact label -------------------------------------------

def orphan_chunks_after_delete(mod):
    store = build(mod)
    ingest(store, mod, attacks.ERIN_TICKET_ID, 1, attacks.ERIN_V1, "acme", ["acme:support"])
    ingest(store, mod, attacks.ERIN_TICKET_ID, 2, attacks.ERIN_V2, "acme", ["acme:support"])
    delete(store, attacks.ERIN_TICKET_ID)
    out = mod.answer(store, who(mod, "sam"), attacks.ERIN_QUESTION)
    return "DELETED DATA SERVED" if leaked(out, attacks.CANARY_ERIN) else "ok"


def cache_after_delete(mod):
    store = build(mod)
    ingest(store, mod, attacks.ERIN_TICKET_ID, 1, attacks.ERIN_V1, "acme", ["acme:support"])
    mod.answer(store, who(mod, "sam"), attacks.ERIN_QUESTION)  # warms the cache
    delete(store, attacks.ERIN_TICKET_ID)
    out = mod.answer(store, who(mod, "sam"), attacks.ERIN_QUESTION)
    return "DELETED DATA SERVED" if leaked(out, attacks.CANARY_ERIN) else "ok"


def backup_resurrection(mod):
    store = build(mod)
    ingest(store, mod, attacks.ERIN_TICKET_ID, 1, attacks.ERIN_V1, "acme", ["acme:support"])
    snapshot = store.backup()             # last night's backup
    delete(store, attacks.ERIN_TICKET_ID)  # today's deletion request
    store.restore(snapshot)               # an incident forces a restore
    out = mod.answer(store, who(mod, "sam"), attacks.ERIN_QUESTION)
    return "DELETED DATA SERVED" if leaked(out, attacks.CANARY_ERIN) else "ok"


def cross_user_cache(mod):
    store = build(mod)
    mod.answer(store, who(mod, "hana"), attacks.HR_QUESTION)       # HR user asks first
    out = mod.answer(store, who(mod, "mallory"), attacks.HR_QUESTION)
    return "CANARY LEAKED" if leaked(out, attacks.CANARY_HR) else "ok"


def metadata_tamper_via_api(mod):
    store = build(mod)
    mallory = who(mod, "mallory")
    try:
        if mod is V:
            store.update_metadata(mallory, "hr-reorg:v1:0", attacks.tamper_patch())
        else:
            store.update_metadata(mallory, "acme", "hr-reorg:v1:0", attacks.tamper_patch())
    except PermissionError:
        pass
    out = mod.answer(store, mallory, attacks.HR_QUESTION)
    return "CANARY LEAKED" if leaked(out, attacks.CANARY_HR) else "ok"


def metadata_tamper_direct_db_write(mod):
    store = build(mod)
    records(store)["hr-reorg:v1:0"]["metadata"].update(attacks.tamper_patch())  # out-of-band edit
    out = mod.answer(store, who(mod, "mallory"), attacks.HR_QUESTION)
    return "CANARY LEAKED" if leaked(out, attacks.CANARY_HR) else "ok"


def _client(mod, store):
    if mod is V:
        return TestClient(V.create_admin_api(store))
    return TestClient(S.create_admin_api(store, {ADMIN_TOKEN: "admin", READER_TOKEN: "reader"}))


def unauthenticated_export(mod):
    store = build(mod)
    resp = _client(mod, store).get("/admin/export")
    if resp.status_code == 200 and leaked(resp.text, attacks.CANARY_HR):
        return "CANARY LEAKED"
    return f"ok ({resp.status_code})"


def vectors_only_inversion(mod):
    """Even an ADMIN export: can the vectors alone be turned back into text?"""
    store = build(mod)
    resp = _client(mod, store).get("/admin/export", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    vectors = [r.get("vector") for r in resp.json().get("records", {}).values() if isinstance(r, dict)]
    recovered = " ".join(attacks.invert_bag_of_words(v) for v in vectors if v)
    return "TEXT RECOVERED" if leaked(recovered, attacks.CANARY_HR) else "ok"


def unauthenticated_reset(mod):
    store = build(mod)
    _client(mod, store).post("/admin/reset")
    return "STORE WIPED" if not records(store) else "ok"


def benign_handbook_question(mod):
    store = build(mod)
    out = mod.answer(store, who(mod, "sam"), "What are the core working hours?")
    return "ok" if "10 to 4" in out else "BROKEN"


CASES = [orphan_chunks_after_delete, cache_after_delete, backup_resurrection, cross_user_cache,
         metadata_tamper_via_api, metadata_tamper_direct_db_write, unauthenticated_export,
         vectors_only_inversion, unauthenticated_reset, benign_handbook_question]


def main() -> None:
    print(f"{'case':34} {'vulnerable':22} secure")
    print("-" * 70)
    for case in CASES:
        print(f"{case.__name__:34} {case(V):22} {case(S)}")
    print("\nSimilarity decides what is RELEVANT. Only access checks decide what is ALLOWED.")
    print("Tip: switch a layer off, e.g. SecureVectorStore(replay_tombstones=False), and re-run.")


if __name__ == "__main__":
    main()
