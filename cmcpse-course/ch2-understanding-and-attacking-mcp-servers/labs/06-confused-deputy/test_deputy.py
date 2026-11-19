"""Confused deputy exercise: vulnerable vs defended.

Run from the repository root:
    .venv/Scripts/python -m pytest cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/06-confused-deputy -v
"""

import pytest

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "deputy")
rpc = d.rpc


def setup(defended, **kw):
    ts = d.TokenService()
    srv = d.BillingServer(ts, d.Datastore(), defended=defended, **kw)
    return ts, srv


def export(srv, tenant, token):
    return rpc.call_tool(srv.handle, "export_invoices", {"tenant": tenant}, token)


@pytest.mark.parametrize("defended", [False, True])
def test_legitimate_user_reads_their_own_tenant(defended):
    ts, srv = setup(defended)
    tok = ts.issue("alice", "acme", ("invoices:read",))
    assert d.CANARY_ACME in export(srv, "acme", tok)


def test_vulnerable_deputy_reads_another_tenant_for_a_low_privilege_caller():
    ts, srv = setup(False)
    mallory = ts.issue("mallory", "evilcorp", ())  # no scopes at all, wrong tenant
    assert d.CANARY_ACME in export(srv, "acme", mallory)


def test_vulnerable_deputy_even_serves_a_caller_with_no_token():
    _, srv = setup(False)
    assert d.CANARY_GLOBEX in export(srv, "globex", None)


def test_a_steered_agent_using_alices_token_cannot_cross_tenants_when_defended():
    ts, srv = setup(True)
    alice = ts.issue("alice", "acme", ("invoices:read",))  # the injected instruction rides alice's own session
    with pytest.raises(RuntimeError, match="forbidden"):
        export(srv, "globex", alice)
    assert any("tenant mismatch" in a for a in srv.audit)


def test_defended_deputy_denies_missing_scope_and_missing_token():
    ts, srv = setup(True)
    with pytest.raises(RuntimeError, match="forbidden"):
        export(srv, "acme", ts.issue("bob", "acme", ()))
    with pytest.raises(RuntimeError, match="forbidden"):
        export(srv, "acme", None)


def test_token_for_another_audience_is_rejected_no_token_passthrough():
    ts, srv = setup(True)
    other = ts.issue("alice", "acme", ("invoices:read",), aud="calendar-mcp")
    with pytest.raises(RuntimeError, match="forbidden"):
        export(srv, "acme", other)
    assert any("wrong audience" in a for a in srv.audit)


def test_row_level_security_still_protects_when_the_server_check_has_a_bug():
    ts, srv = setup(True, check_in_server=False)  # simulate a forgotten ownership check in the server
    alice = ts.issue("alice", "acme", ("invoices:read",))
    with pytest.raises(RuntimeError, match="forbidden|row-level"):
        export(srv, "globex", alice)


def test_audit_log_names_the_caller_on_allow_and_deny():
    ts, srv = setup(True)
    tok = ts.issue("alice", "acme", ("invoices:read",))
    export(srv, "acme", tok)
    with pytest.raises(RuntimeError):
        export(srv, "globex", tok)
    assert srv.audit == ["allow acme for alice", "deny globex for alice: tenant mismatch"]


# ----- OAuth proxy variant -----
def test_static_client_id_proxy_lets_an_attacker_client_ride_the_victims_consent():
    p = d.OAuthProxy(per_client_consent=False)
    p.register("good-app", "https://app.example/cb")
    p.user_consents("victim", "good-app", "https://app.example/cb")      # consent given once, to the good app
    p.register("evil-app", "https://evil.example/cb")
    link = p.authorize("victim", "evil-app", "https://evil.example/cb")  # victim clicks the attacker's link
    assert link.startswith("https://evil.example/cb?code=")


def test_per_client_consent_and_exact_redirect_stop_the_attack():
    p = d.OAuthProxy(per_client_consent=True)
    p.register("good-app", "https://app.example/cb")
    p.user_consents("victim", "good-app", "https://app.example/cb")
    p.register("evil-app", "https://evil.example/cb")
    assert p.authorize("victim", "evil-app", "https://evil.example/cb") == "consent_required"
    assert "redirect_uri does not match" in p.authorize("victim", "good-app", "https://evil.example/cb")
    assert p.authorize("victim", "good-app", "https://app.example/cb").startswith("https://app.example/cb?code=")
