import json

import pytest

from aisec_lab import load_lab_module

mv = load_lab_module(__file__, "mini_vault")
CANARY = "CANARY-secret-value-123"


def make(backend=None):
    clock = mv.Clock()
    vault, root, unseal = mv.bootstrap(backend, clock)
    rec = mv.RecordingTransport(mv.InProcessTransport(vault))
    return vault, clock, rec, mv.VaultClient(rec, root), unseal


def policy(admin, name, rules):
    admin.call("POST", f"sys/policies/acl/{name}", {"policy": rules})


def child(admin, rec, policies, ttl=600):
    tok = admin.call("POST", "auth/token/create", {"policies": policies, "ttl": ttl})["auth"]["client_token"]
    return mv.VaultClient(rec, tok)


# ---------------------------------------------------------------- seal, storage, auth
def test_unseal_cycle():
    vault, _c, _r, admin, unseal = make()
    vault.seal()
    assert vault.request("GET", "secret/data/x", admin.token)[0] == 503
    assert vault.unseal(mv.b64e(b"x" * 32)) is False and vault.sealed
    assert vault.unseal(unseal) is True
    assert vault.request("GET", "sys/seal-status")[1]["sealed"] is False


def test_unseal_with_garbage_is_rejected_not_crashing():
    vault, *_ = make()
    vault.seal()
    assert vault.request("POST", "sys/unseal", None, {"key": "***not-base64***"})[0] == 400


@pytest.mark.parametrize("backend_cls", [mv.ConsulLikeKV, mv.RaftIntegratedStorage])
def test_storage_backend_sees_only_ciphertext(backend_cls):
    backend = backend_cls()
    _v, _c, _r, admin, _u = make(backend)
    admin.kv_put("app/db", {"password": CANARY})
    dump = backend.raw_dump()
    assert dump and all(CANARY.encode() not in blob for blob in dump.values())
    assert all(b"password" not in blob for blob in dump.values())
    assert backend.kind in {"consul", "raft"}


def test_token_auth_required():
    vault, _c, _r, admin, _u = make()
    assert vault.request("GET", "secret/data/x")[0] == 403
    assert vault.request("GET", "secret/data/x", "mvt.not-a-real-token")[0] == 403
    admin.kv_put("x", {"a": 1})
    assert admin.kv_get("x") == {"a": 1}


def test_token_expiry_and_renewal_capped_by_max_ttl():
    vault, clock, rec, admin, _u = make()
    tok = admin.call("POST", "auth/token/create", {"policies": ["root"], "ttl": 60, "max_ttl": 300})["auth"]["client_token"]
    c = mv.VaultClient(rec, tok)
    clock.advance(30)
    assert c.call("POST", "auth/token/renew-self", {"increment": 1000})["auth"]["lease_duration"] == 270  # capped at max_ttl
    clock.advance(271)
    assert vault.request("GET", "auth/token/lookup-self", tok)[0] == 403


def test_revoke_self():
    vault, _c, rec, admin, _u = make()
    c = child(admin, rec, [])
    c.call("POST", "auth/token/revoke-self")
    assert vault.request("GET", "auth/token/lookup-self", c.token)[0] == 403


def test_child_token_cannot_exceed_parent_policies():
    _v, _c, rec, admin, _u = make()
    policy(admin, "a", {"secret/data/a/*": ["read", "update"]})
    policy(admin, "b", {"secret/data/b/*": ["read"]})
    policy(admin, "mint", {"auth/token/create": ["update"], "secret/data/a/*": ["read"]})
    parent = child(admin, rec, ["mint", "a"])
    parent.call("POST", "auth/token/create", {"policies": ["a"]})
    with pytest.raises(mv.VaultError):
        parent.call("POST", "auth/token/create", {"policies": ["b"]})


def test_approle_secret_id_is_single_use():
    vault, _c, rec, admin, _u = make()
    policy(admin, "app", {"secret/data/app/*": ["read"]})
    admin.call("POST", "auth/approle/role/web", {"policies": ["app"], "token_ttl": 120})
    rid = admin.call("GET", "auth/approle/role/web/role-id")["data"]["role_id"]
    sid = admin.call("POST", "auth/approle/role/web/secret-id")["data"]["secret_id"]
    app = mv.VaultClient(rec)
    app.approle_login(rid, sid)
    assert app.call("GET", "auth/token/lookup-self")["data"]["policies"] == ["app"]
    with pytest.raises(mv.VaultError):
        mv.VaultClient(rec).approle_login(rid, sid)
    sid2 = admin.call("POST", "auth/approle/role/web/secret-id")["data"]["secret_id"]
    with pytest.raises(mv.VaultError):
        mv.VaultClient(rec).approle_login("role-wrong", sid2)


# ---------------------------------------------------------------- policies
def test_policy_path_acl_least_privilege():
    vault, _c, rec, admin, _u = make()
    policy(admin, "app-read", {"secret/data/app/*": ["read"]})
    admin.kv_put("app/db", {"p": 1})
    admin.kv_put("other/db", {"p": 2})
    app = child(admin, rec, ["app-read"])
    assert app.kv_get("app/db") == {"p": 1}
    assert vault.request("GET", "secret/data/other/db", app.token)[0] == 403
    assert vault.request("POST", "secret/data/app/db", app.token, {"data": {"p": 9}})[0] == 403
    assert vault.request("POST", "sys/policies/acl/evil", app.token, {"policy": {"*": ["read"]}})[0] == 403


def test_deny_overrides_and_plus_wildcard():
    vault, _c, rec, admin, _u = make()
    policy(admin, "p", {"secret/data/+/db": ["read"], "secret/data/prod/db": ["deny"]})
    admin.kv_put("dev/db", {"x": 1})
    admin.kv_put("prod/db", {"x": 2})
    c = child(admin, rec, ["p"])
    assert c.kv_get("dev/db") == {"x": 1}
    assert vault.request("GET", "secret/data/prod/db", c.token)[0] == 403


def test_unknown_capability_rejected():
    _v, _c, _r, admin, _u = make()
    with pytest.raises(mv.VaultError):
        policy(admin, "bad", {"x/*": ["god-mode"]})


# ---------------------------------------------------------------- KV v2
def test_kv_versions_and_old_version_read():
    _v, _c, _r, admin, _u = make()
    assert admin.kv_put("app/db", {"pw": "one"}) == 1
    assert admin.kv_put("app/db", {"pw": "two"}) == 2
    assert admin.kv_get("app/db") == {"pw": "two"}
    assert admin.kv_get("app/db", version=1) == {"pw": "one"}
    meta = admin.call("GET", "secret/metadata/app/db")["data"]
    assert meta["current_version"] == 2 and set(meta["versions"]) == {"1", "2"}


def test_kv_check_and_set():
    _v, _c, _r, admin, _u = make()
    admin.kv_put("k", {"a": 1}, cas=0)
    admin.kv_put("k", {"a": 2}, cas=1)
    with pytest.raises(mv.VaultError):
        admin.kv_put("k", {"a": 3}, cas=1)  # stale: someone else wrote version 2


def test_kv_delete_undelete_destroy():
    vault, _c, _r, admin, _u = make()
    admin.kv_put("k", {"a": 1})
    admin.call("DELETE", "secret/data/k")
    assert vault.request("GET", "secret/data/k", admin.token)[0] == 404
    admin.call("POST", "secret/undelete/k", {"versions": [1]})
    assert admin.kv_get("k") == {"a": 1}
    admin.call("POST", "secret/destroy/k", {"versions": [1]})
    assert vault.request("GET", "secret/data/k", admin.token)[0] == 404


def test_kv_max_versions_prunes_oldest_and_list():
    vault, _c, _r, admin, _u = make()
    for i in range(7):
        admin.kv_put("app/rot", {"n": i})
    meta = admin.call("GET", "secret/metadata/app/rot")["data"]
    assert set(meta["versions"]) == {"3", "4", "5", "6", "7"}
    assert vault.request("GET", "secret/data/app/rot", admin.token, None, {"version": 1})[0] == 404
    admin.kv_put("app/sub/x", {"a": 1})
    keys = admin.call("GET", "secret/metadata/app", query={"list": "true"})["data"]["keys"]
    assert "rot" in keys and "sub/" in keys


# ---------------------------------------------------------------- transit
def test_transit_roundtrip_and_app_never_sees_the_key():
    vault, _c, rec, admin, _u = make()
    policy(admin, "crypto", {"transit/encrypt/orders": ["update"], "transit/decrypt/orders": ["update"]})
    admin.call("POST", "transit/keys/orders")
    app = child(admin, rec, ["crypto"])
    ct = app.encrypt("orders", b"card 4242", context="o1")
    assert ct.startswith("vault:v1:")
    assert app.decrypt("orders", ct, context="o1") == b"card 4242"
    key_b64 = vault._get("transit/orders")["versions"]["1"]["key"]
    raw = mv.b64d(key_b64)
    seen = rec.transcript
    assert key_b64 not in seen and raw.hex() not in seen and key_b64.rstrip("=") not in seen
    # the admin read the key metadata: still no key
    meta = admin.call("GET", "transit/keys/orders")["data"]
    assert meta["exportable"] is False and "key" not in json.dumps(meta).lower().replace("keys", "")
    assert key_b64 not in rec.transcript


def test_transit_key_has_no_export_path_even_for_root():
    vault, _c, _r, admin, _u = make()
    admin.call("POST", "transit/keys/orders")
    for path in ("transit/export/encryption-key/orders", "transit/keys/orders/export"):
        assert vault.request("GET", path, admin.token)[0] == 404


def test_transit_separation_of_duties():
    vault, _c, rec, admin, _u = make()
    policy(admin, "ingest", {"transit/encrypt/orders": ["update"]})
    policy(admin, "report", {"transit/decrypt/orders": ["update"]})
    admin.call("POST", "transit/keys/orders")
    ingest, report = child(admin, rec, ["ingest"]), child(admin, rec, ["report"])
    ct = ingest.encrypt("orders", b"secret-note")
    assert vault.request("POST", "transit/decrypt/orders", ingest.token, {"ciphertext": ct})[0] == 403
    assert report.decrypt("orders", ct) == b"secret-note"
    assert vault.request("GET", "transit/keys/orders", ingest.token)[0] == 403


def test_transit_rotation_rewrap_and_old_versions():
    _v, _c, _r, admin, _u = make()
    admin.call("POST", "transit/keys/k")
    old = admin.encrypt("k", b"data")
    admin.call("POST", "transit/keys/k/rotate")
    assert admin.decrypt("k", old) == b"data"  # old ciphertext still decrypts
    new = admin.call("POST", "transit/rewrap/k", {"ciphertext": old})["data"]["ciphertext"]
    assert old.startswith("vault:v1:") and new.startswith("vault:v2:")
    assert admin.decrypt("k", new) == b"data"
    assert admin.encrypt("k", b"x").startswith("vault:v2:")


def test_transit_context_binding_and_tamper_detection():
    _v, _c, _r, admin, _u = make()
    admin.call("POST", "transit/keys/k")
    ct = admin.encrypt("k", b"data", context="tenant-a")
    with pytest.raises(mv.VaultError):
        admin.decrypt("k", ct, context="tenant-b")
    prefix, blob = ct.rsplit(":", 1)
    raw = bytearray(mv.b64d(blob))
    raw[-1] ^= 1
    with pytest.raises(mv.VaultError):
        admin.decrypt("k", f"{prefix}:{mv.b64e(bytes(raw))}", context="tenant-a")


def test_cipher_primitives():
    key = b"k" * 32
    blob = mv.seal_bytes(key, b"hello", b"aad")
    assert mv.open_bytes(key, blob, b"aad") == b"hello"
    assert mv.seal_bytes(key, b"hello", b"aad") != blob  # fresh nonce each time
    with pytest.raises(mv.VaultError):
        mv.open_bytes(b"x" * 32, blob, b"aad")
    assert "NOT REAL CRYPTO" in mv.__doc__


# ---------------------------------------------------------------- leases and dynamic secrets
def test_dynamic_creds_expire_and_are_dropped():
    vault, clock, rec, admin, _u = make()
    admin.call("POST", "database/roles/ro", {"default_ttl": 300, "max_ttl": 900})
    c = admin.db_creds("ro")
    user, pw = c["data"]["username"], c["data"]["password"]
    assert user.startswith("v-ro-") and vault.database.login_ok(user, pw)
    clock.advance(299)
    vault.request("GET", "sys/seal-status")
    assert vault.database.login_ok(user, pw)
    clock.advance(2)
    vault.request("GET", "sys/seal-status")  # any request lets the server reap expired leases
    assert not vault.database.login_ok(user, pw)
    assert vault.database.login_ok("app_static", "static-password-CANARY")  # static account untouched


def test_each_credential_request_gets_a_unique_user():
    _v, _c, _r, admin, _u = make()
    admin.call("POST", "database/roles/ro", {})
    a, b = admin.db_creds("ro"), admin.db_creds("ro")
    assert a["data"]["username"] != b["data"]["username"] and a["lease_id"] != b["lease_id"]


def test_lease_renewal_is_capped_and_revoke_is_immediate():
    vault, clock, _r, admin, _u = make()
    admin.call("POST", "database/roles/ro", {"default_ttl": 300, "max_ttl": 600})
    c = admin.db_creds("ro")
    clock.advance(200)
    r = admin.call("POST", "sys/leases/renew", {"lease_id": c["lease_id"], "increment": 5000})
    assert r["lease_duration"] == 400  # 600 max from issue minus the 200 s already used
    admin.call("POST", "sys/leases/revoke", {"lease_id": c["lease_id"]})
    assert not vault.database.login_ok(c["data"]["username"], c["data"]["password"])
    with pytest.raises(mv.VaultError):
        admin.call("POST", "sys/leases/renew", {"lease_id": c["lease_id"]})


# ---------------------------------------------------------------- audit and HTTP
def test_audit_log_never_contains_secret_values_or_raw_tokens():
    vault, _c, _r, admin, _u = make()
    admin.kv_put("app/db", {"password": CANARY})
    admin.kv_get("app/db")
    text = json.dumps(vault.audit_log)
    assert CANARY not in text and admin.token not in text
    assert any(e["path"] == "secret/data/app/db" and e["request_keys"] == ["data"] for e in vault.audit_log)


def test_http_wrapper_on_loopback():
    vault, _c, _r, admin, _u = make()
    httpd, thread, url = mv.serve(vault)
    try:
        assert url.startswith("http://127.0.0.1:")
        t = mv.HttpTransport(url)
        assert t("GET", "secret/data/x", None)[0] == 403
        client = mv.VaultClient(t, admin.token)
        assert client.kv_put("web/x", {"a": "b"}) == 1
        assert client.kv_get("web/x") == {"a": "b"}
        assert t("GET", "sys/seal-status", None)[1]["storage_type"] == "consul"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_consul_like_backend_cas_and_index():
    b = mv.ConsulLikeKV()
    assert b.put("k", b"1", cas=0) is True and b.put("k", b"2", cas=0) is False
    _v, idx = b.get("k")
    assert b.put("k", b"3", cas=idx) is True and b.put("k", b"4", cas=idx) is False
    assert b.get("k")[1] > idx
