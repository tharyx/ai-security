"""Tests for oauth_scopes.py. Run: python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers"""

from __future__ import annotations

from aisec_lab import load_lab_module

os_ = load_lab_module(__file__, "oauth_scopes")
KEY = b"k" * 32


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def setup(**kw):
    clock = Clock()
    issuer = os_.Issuer(KEY, now=clock)
    server = os_.ScopedServer(KEY, now=clock, **kw)
    return clock, issuer, server


def call(server, token, tool, **args):
    return server.handle(token, "tools/call", {"name": tool, "arguments": args})


def test_valid_reader_can_read_but_not_write():
    _, iss, srv = setup()
    tok = iss.mint("alice", "reader-app", ["notes:read"], os_.AUDIENCE)
    assert call(srv, tok, "notes.read", id="n1") == {"result": "hello"}
    r = call(srv, tok, "notes.write", id="n2", text="x")
    assert r["error"]["status"] == 403 and r["error"]["code"] == "insufficient_scope"
    assert "notes:write" in r["error"]["detail"]          # the 403 names the missing scope
    assert "notes:write" in r["error"]["www_authenticate"]
    assert "n2" not in srv.notes


def test_delete_needs_both_scopes():
    _, iss, srv = setup()
    editor = iss.mint("bob", "editor-app", ["notes:read", "notes:write"], os_.AUDIENCE)
    assert call(srv, editor, "notes.delete", id="n1")["error"]["code"] == "insufficient_scope"
    admin = iss.mint("root", "admin-app", ["notes:read", "notes:write", "notes:delete"], os_.AUDIENCE)
    assert call(srv, admin, "notes.delete", id="n1") == {"result": "deleted"}


def test_wrong_audience_is_rejected_with_401():
    _, iss, srv = setup()
    tok = iss.mint("alice", "admin-app", ["notes:read", "notes:write", "notes:delete"], os_.OTHER_AUDIENCE)
    r = call(srv, tok, "notes.read", id="n1")
    assert r["error"]["status"] == 401 and "audience" in r["error"]["detail"]
    assert "resource_metadata" in r["error"]["www_authenticate"]


def test_multi_audience_token_is_accepted_only_if_we_are_listed():
    _, iss, srv = setup()
    ok = iss.mint("a", "reader-app", ["notes:read"], [os_.OTHER_AUDIENCE, os_.AUDIENCE])
    assert "result" in call(srv, ok, "notes.read", id="n1")


def test_without_audience_check_the_stolen_token_works_confused_deputy():
    _, iss, srv = setup(check_audience=False)
    tok = iss.mint("alice", "reader-app", ["notes:read"], os_.OTHER_AUDIENCE)
    assert "result" in call(srv, tok, "notes.read", id="n1")   # the bug the check prevents


def test_over_scoped_token_is_rejected_even_if_signature_is_valid():
    _, iss, srv = setup()
    wild = iss.mint("mallory", "reader-app", ["notes:read", "*"], os_.AUDIENCE)
    r = call(srv, wild, "notes.read", id="n1")
    assert r["error"]["status"] == 403 and r["error"]["code"] == "over_scoped"
    extra = iss.mint("mallory", "reader-app", ["notes:read", "notes:delete"], os_.AUDIENCE)   # more than the client may hold
    assert call(srv, extra, "notes.read", id="n1")["error"]["code"] == "over_scoped"
    unknown = iss.mint("mallory", "unknown-app", ["notes:read"], os_.AUDIENCE)
    assert call(srv, unknown, "notes.read", id="n1")["error"]["code"] == "over_scoped"


def test_over_scope_check_can_be_disabled_to_show_the_risk():
    _, iss, srv = setup(check_over_scope=False)
    wild = iss.mint("mallory", "reader-app", ["notes:read", "notes:write", "notes:delete"], os_.AUDIENCE)
    assert call(srv, wild, "notes.delete", id="n1") == {"result": "deleted"}


def test_tampered_forged_expired_and_missing_tokens():
    clock, iss, srv = setup()
    tok = iss.mint("alice", "reader-app", ["notes:read"], os_.AUDIENCE, ttl=60)
    head, body, sig = tok.split(".")
    forged_body = os_._b64(b'{"iss":"https://auth.acme.example","sub":"x","client_id":"admin-app","scope":"notes:delete notes:write notes:read","aud":"https://notes-mcp.acme.example","exp":99999999999}')
    for bad in (f"{head}.{forged_body}.{sig}", "not-a-token", f"{head}.{body}.", tok + "x"):
        r = call(srv, bad, "notes.read", id="n1")
        assert r["error"]["status"] == 401, bad
    assert call(srv, None, "notes.read", id="n1")["error"]["detail"] == "missing token"
    clock.t += 61
    assert call(srv, tok, "notes.read", id="n1")["error"]["detail"] == "expired"


def test_wrong_issuer_is_rejected():
    clock = Clock()
    other = os_.Issuer(KEY, issuer="https://evil.example", now=clock)
    srv = os_.ScopedServer(KEY, now=clock)
    tok = other.mint("a", "reader-app", ["notes:read"], os_.AUDIENCE)
    assert call(srv, tok, "notes.read", id="n1")["error"]["detail"] == "wrong issuer"


def test_unlisted_tool_is_denied_by_default():
    _, iss, srv = setup()
    tok = iss.mint("root", "admin-app", ["notes:read", "notes:write", "notes:delete"], os_.AUDIENCE)
    assert call(srv, tok, "notes.export")["error"]["code"] == "tool_not_allowed"


def test_tools_list_only_shows_tools_the_token_can_call():
    _, iss, srv = setup()
    tok = iss.mint("alice", "reader-app", ["notes:read"], os_.AUDIENCE)
    assert srv.handle(tok, "tools/list") == {"result": {"tools": [{"name": "notes.read"}]}}


def test_audit_records_denials_without_the_token():
    _, iss, srv = setup()
    tok = iss.mint("alice", "reader-app", ["notes:read"], os_.AUDIENCE)
    call(srv, tok, "notes.write", id="x", text="y")
    call(srv, tok, "notes.read", id="n1")
    assert [e["decision"] for e in srv.log] == ["deny", "allow"]
    assert tok not in str(srv.log)
