import json

import pytest
from aisec_lab import load_lab_module

vl = load_lab_module(__file__, "vault_lite")


def test_hardcoded_service_breaks_on_rotation_and_leaks_secret_in_logs():
    db = vl.FakeDatabase()
    pw = vl.fake_secret("x")
    db.create_user("app", pw)
    svc = vl.HardcodedOrdersService(db, {"db_user": "app", "db_password": pw})
    db.create_user("app", vl.fake_secret("rotated"))
    assert svc.query() == "error" and pw in svc.log[0]


def test_approle_login_and_least_privilege_policy():
    v, admin, role_id, sid = vl.bootstrap()
    s = vl.VaultOrdersService(v, role_id, sid)
    assert s.api_key_for_payments().startswith("FAKE-payments-")
    with pytest.raises(vl.VaultError) as e:
        v.kv_get(s.token, "billing/provider")
    assert e.value.status == 403
    with pytest.raises(vl.VaultError):
        v.kv_put(s.token, "orders/payments", {"api_key": "x"})  # read-only policy


def test_secret_id_is_single_use():
    v, _, role_id, sid = vl.bootstrap()
    vl.VaultOrdersService(v, role_id, sid)
    with pytest.raises(vl.VaultError):
        v.approle_login(role_id, sid)


def test_dynamic_db_credentials_are_unique_and_work():
    v, _, role_id, _ = vl.bootstrap()
    a = vl.VaultOrdersService(v, role_id, v.generate_secret_id(role_id))
    b = vl.VaultOrdersService(v, role_id, v.generate_secret_id(role_id))
    assert a.creds["data"]["username"] != b.creds["data"]["username"]
    assert a.query() == "rows" and b.query() == "rows"


def test_lease_expiry_drops_the_db_user_and_token_expires():
    v, _, role_id, sid = vl.bootstrap()
    s = vl.VaultOrdersService(v, role_id, sid)
    user = s.creds["data"]["username"]
    v.clock.advance(601); v._expire()
    assert user not in v.db.users
    v.clock.advance(300)
    with pytest.raises(vl.VaultError):
        s.api_key_for_payments()


def test_renewal_is_capped_by_max_ttl():
    v, _, role_id, sid = vl.bootstrap()
    s = vl.VaultOrdersService(v, role_id, sid)
    for _ in range(4):
        v.clock.advance(500)
        s.heartbeat()  # renewals keep the lease (600 s) and token (900 s) alive
    assert s.query() == "rows"
    v.clock.advance(800)  # t=2800: past the lease max TTL (4 x 600 s)
    with pytest.raises(vl.VaultError):
        s.heartbeat()


def test_rotation_is_picked_up_without_redeploy():
    v, admin, role_id, sid = vl.bootstrap()
    s = vl.VaultOrdersService(v, role_id, sid)
    new = vl.fake_secret("v2")
    assert v.kv_put(admin, "orders/payments", {"api_key": new}) == 2
    assert s.api_key_for_payments() == new
    assert v.kv_get(admin, "orders/payments", version=1)["metadata"]["version"] == 1


def test_audit_log_has_hmacs_not_secrets_or_tokens():
    v, admin, role_id, sid = vl.bootstrap()
    s = vl.VaultOrdersService(v, role_id, sid)
    key = s.api_key_for_payments()
    dump = json.dumps(v.audit)
    assert key not in dump and s.token not in dump and s.creds["data"]["password"] not in dump
    assert "hmac-sha256:" in dump
    assert not any(s.creds["data"]["password"] in line for line in s.log)
