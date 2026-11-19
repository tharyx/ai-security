import secrets
import sqlite3

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "principles")
ACL = {"clerk": {"read"}, "admin": {"read", "delete"}}


def test_economy_of_mechanism_forgotten_legacy_path_lets_anyone_be_admin():
    vuln = p.ManyPathAuth(sessions={}, api_keys={})
    simple = p.OnePathAuth(tokens={})
    attack = {"X-Internal-User": "admin"}
    assert vuln.authenticate(attack) == "admin"
    assert simple.authenticate(attack) is None


def test_fail_open_grants_unknown_role_fail_safe_denies():
    intruder = {"name": "x"}  # no role at all
    assert p.allowed_fail_open(intruder, "delete", ACL) is True
    assert p.allowed_fail_safe(intruder, "delete", ACL) is False
    assert p.allowed_fail_safe({"role": "admin"}, "delete", ACL) is True


def test_complete_mediation_revocation_takes_effect_immediately():
    for cls, still_allowed in ((p.CachedAuthz, True), (p.MediatedAuthz, False)):
        store = {"mallory": {"delete"}}
        authz = cls(store)
        sid = authz.login("mallory")
        store["mallory"].discard("delete")  # HR revokes access after the login
        assert authz.can(sid, "delete") is still_allowed


def test_open_design_attacker_who_knows_the_format_forges_obscure_token_only():
    forged = p.obscure_token(1)  # attacker read the code / reversed the app
    assert p.obscure_verify(forged) == 1
    key = secrets.token_bytes(32)
    forged_open = "1." + "0" * 64
    assert p.open_verify(forged_open, key) is None
    assert p.open_verify(p.open_token(1, key), key) == 1


def test_separation_of_privilege_requester_cannot_approve_large_refund_alone():
    assert p.refund_single_key(50_000, "eve", ["eve"]) is True
    assert p.refund_two_person(50_000, "eve", ["eve", "bob"]) is False
    assert p.refund_two_person(50_000, "eve", ["bob", "carol"]) is True
    assert p.refund_two_person(500, "eve", ["bob"]) is True


def test_least_privilege_report_user_cannot_delete_data():
    owner = p.report_db(least_privilege=False)
    p.run_report(owner, "DELETE FROM orders")
    assert owner.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0
    reader = p.report_db(least_privilege=True)
    assert p.run_report(reader, "SELECT customer FROM orders ORDER BY id") == [("alice",), ("bob",)]
    with pytest.raises(sqlite3.DatabaseError):
        p.run_report(reader, "DELETE FROM orders")


def test_least_common_mechanism_shared_cache_leaks_between_tenants():
    def build(tenant, report):
        return f"{report} for {tenant}"

    shared, isolated = p.SharedReportCache(), p.TenantReportCache()
    shared.get("acme", "revenue", build)
    isolated.get("acme", "revenue", build)
    assert shared.get("globex", "revenue", build) == "revenue for acme"   # leak
    assert isolated.get("globex", "revenue", build) == "revenue for globex"


def test_psychological_acceptability_usable_policy_rejects_predictable_and_accepts_passphrase():
    predictable, passphrase = "Summer2026!", "correct horse battery staple"
    assert p.complexity_policy(predictable) and not p.complexity_policy(passphrase)
    assert p.usable_policy(passphrase) and not p.usable_policy(predictable)
    assert not p.usable_policy("Password-Password-1")
