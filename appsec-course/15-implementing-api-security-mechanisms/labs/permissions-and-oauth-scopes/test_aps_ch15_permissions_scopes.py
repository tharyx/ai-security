from pathlib import Path

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "scopes")
FX = Path(__file__).resolve().parent / "fixtures"
WEAK, SECURE, CLIENTS = s.load(FX / "spec_weak.json"), s.load(FX / "spec_secure.json"), s.load(FX / "clients.json")
OWNERS = {"1001": "asha", "1002": "ravi"}.get


def ids(findings):
    return {f.id for f in findings}


def test_weak_spec_design_flaws_are_found():
    got = ids(s.lint_spec(WEAK))
    assert {"SCOPE-01", "SCOPE-02", "SCOPE-03", "SCOPE-04", "SCOPE-06", "SCOPE-09"} <= got


def test_reviewed_spec_is_clean_except_overgranted_client():
    found = s.lint_spec(SECURE, CLIENTS)
    assert ids(found) == {"SCOPE-05"}
    assert "reporting-job" in found[0].message and "refunds:admin" in found[0].message


def test_matrix_lists_every_endpoint_and_scope():
    m = s.matrix(SECURE)
    assert m.count("\n") == len(SECURE["endpoints"]) + 1
    assert "refunds:admin" in m.splitlines()[0]


def test_read_only_token_can_delete_on_vulnerable_but_not_secure():
    claims = {"sub": "asha", "roles": ["customer"], "scope": "orders:read"}
    assert s.authorize_vulnerable(claims, "DELETE", "/orders/1001", SECURE).allow
    assert not s.authorize_secure(claims, "DELETE", "/orders/1001", SECURE, OWNERS).allow


def test_bola_blocked_by_owner_check():
    claims = {"sub": "asha", "roles": ["customer"], "scope": "orders:read"}
    assert s.authorize_vulnerable(claims, "GET", "/orders/1002", SECURE).allow
    d = s.authorize_secure(claims, "GET", "/orders/1002", SECURE, OWNERS)
    assert not d.allow and "belongs to ravi" in d.reason
    assert s.authorize_secure(claims, "GET", "/orders/1001", SECURE, OWNERS).allow


def test_scope_in_token_does_not_grant_beyond_user_role():
    claims = {"sub": "meena", "roles": ["support"], "scope": "orders:read refunds:admin"}
    d = s.authorize_secure(claims, "POST", "/admin/refunds", SECURE, OWNERS)
    assert not d.allow and "ceiling" in d.reason
    fin = {"sub": "kiran", "roles": ["finance"], "scope": "refunds:admin"}
    assert s.authorize_secure(fin, "POST", "/admin/refunds", SECURE, OWNERS).allow


def test_unknown_routes_and_scope_less_endpoints_are_denied_by_default():
    claims = {"sub": "asha", "roles": ["customer"], "scope": "orders:read orders:write"}
    assert s.authorize_vulnerable(claims, "GET", "/internal/export", SECURE).allow
    assert not s.authorize_secure(claims, "GET", "/internal/export", SECURE).allow
    assert not s.authorize_secure(claims, "POST", "/orders", WEAK).allow  # endpoint defined with no scope


def test_public_endpoint_needs_no_token_and_missing_token_is_denied():
    assert s.authorize_secure(None, "GET", "/health", SECURE).allow
    assert not s.authorize_secure(None, "GET", "/orders", SECURE).allow
