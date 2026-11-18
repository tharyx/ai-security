"""Regression tests: each token attack must work on the vulnerable server and fail on the secure server.

Run from the repository root:
    python -m pytest 04-mcp-security/authentication -v
"""

import secrets

import pytest

from aisec_lab import load_lab_module

attacks = load_lab_module(__file__, "attacks")
authmod = load_lab_module(__file__, "auth_server")
vuln = load_lab_module(__file__, "vulnerable_server")
sec = load_lab_module(__file__, "secure_server")

NOW = 1_800_000_000.0
BOB_SECRET_MARKER = "CANARY-BOB"


class World:
    """A fresh authorization server, downstream API and both MCP servers, on a frozen clock."""

    def __init__(self, **secure_flags):
        self.auth = authmod.AuthorizationServer(now=lambda: NOW)
        self.api = authmod.TicketsAPI(self.auth)
        self.vulnerable = vuln.VulnerableDocsMCPServer(self.auth.key, self.api, authmod.ADMIN_API_KEY)
        self.secure = sec.SecureDocsMCPServer(self.auth.key, self.api, self.auth.exchange,
                                              now=lambda: NOW, **secure_flags)

    def token(self, case):
        return authmod.forge_unsigned(case["forge"]) if "forge" in case else self.auth.mint(**case["mint"])

    def send(self, server, case, token=None):
        token = token or self.token(case)
        return server.handle({"headers": {"Authorization": f"Bearer {token}"}, "body": case["body"]}), token


# ---------- Part 1: prove the attacks are real -------------------------------------------

def test_forged_unsigned_token_closes_bobs_ticket_on_vulnerable_server():
    w = World()
    resp, _ = w.send(w.vulnerable, attacks.ATTACKS["forged_alg_none"])
    assert resp["status"] == 200 and w.api.tickets["T-2"]["status"] == "closed"


@pytest.mark.parametrize("name", ["expired_token", "wrong_audience_replay"])
def test_vulnerable_server_accepts_invalid_tokens(name):
    w = World()
    resp, _ = w.send(w.vulnerable, attacks.ATTACKS[name])
    assert resp["status"] == 200


def test_confused_deputy_leaks_bobs_ticket_to_alice():
    w = World()
    resp, _ = w.send(w.vulnerable, attacks.ATTACKS["cross_user_read"])
    assert BOB_SECRET_MARKER in str(resp["body"])
    assert w.api.received[-1]["api_key"] == authmod.ADMIN_API_KEY  # the shared key did it


def test_vulnerable_server_passes_the_users_token_downstream():
    w = World()
    resp, token = w.send(w.vulnerable, attacks.ATTACKS["broad_token_passthrough"])
    assert resp["status"] == 200
    assert w.api.received[-1]["bearer"] == token


def test_vulnerable_server_logs_bearer_tokens():
    w = World()
    _, token = w.send(w.vulnerable, attacks.BENIGN)
    assert token in str(w.vulnerable.log)


# ---------- Part 2: the secure server holds ------------------------------------------------

@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_secure_server_blocks_every_attack(name):
    w = World()
    resp, token = w.send(w.secure, attacks.ATTACKS[name])
    assert resp["status"] in (401, 403)
    assert all(t["status"] == "open" for t in w.api.tickets.values())    # no action ran
    assert BOB_SECRET_MARKER not in str(resp["body"])                    # no data leaked
    assert all(r["bearer"] != token for r in w.api.received)             # token never forwarded


def test_benign_call_works_and_uses_an_exchanged_token():
    w = World()
    resp, token = w.send(w.secure, attacks.BENIGN)
    assert resp["status"] == 200 and resp["body"]["result"]["id"] == "T-1"
    sent = w.api.received[-1]["bearer"]
    assert sent != token
    claims = w.auth.introspect(sent, audience=authmod.TICKETS_API)
    assert claims["sub"] == "alice"                                  # user identity preserved
    assert claims["act"] == {"sub": authmod.DOCS_MCP}                # the actor is recorded
    assert claims["exp"] - claims["iat"] == 60                       # short-lived
    assert claims["scope"] == "tickets:read"                         # only the tool's scope


def test_401_points_the_client_to_protected_resource_metadata():
    w = World()
    resp = w.secure.handle({"headers": {}, "body": attacks.BENIGN["body"]})
    assert resp["status"] == 401
    assert 'resource_metadata="https://docs-mcp.acme.example/.well-known/oauth-protected-resource"' \
        in resp["headers"]["WWW-Authenticate"]
    meta = w.secure.protected_resource_metadata()
    assert meta["resource"] == authmod.DOCS_MCP and meta["authorization_servers"] == [authmod.ISSUER]


def test_403_names_the_missing_scope():
    w = World()
    resp, _ = w.send(w.secure, attacks.ATTACKS["missing_scope"])
    assert 'error="insufficient_scope", scope="tickets:write"' in resp["headers"]["WWW-Authenticate"]


def test_token_in_query_string_is_refused():
    w = World()
    token = w.token(attacks.BENIGN)
    resp = w.secure.handle({"query": {"access_token": token}, "headers": {}, "body": attacks.BENIGN["body"]})
    assert resp["status"] == 400


def test_secure_log_has_fingerprints_not_tokens():
    w = World()
    _, token = w.send(w.secure, attacks.BENIGN)
    assert token not in str(w.secure.log)
    assert w.secure.log[-1]["token_fp"] == sec.fingerprint(token)
    assert w.secure.log[-1]["sub"] == "alice" and len(w.secure.log[-1]["correlation_id"]) == 12


def test_token_signed_with_another_key_is_rejected():
    w = World()
    other = authmod.AuthorizationServer(now=lambda: NOW, key=secrets.token_bytes(32))
    resp, _ = w.send(w.secure, attacks.BENIGN, token=other.mint("alice", authmod.DOCS_MCP, "tickets:read"))
    assert resp["status"] == 401


# ---------- Part 3: defense in depth - layers back each other up -----------------------------

def test_without_scope_check_the_exchange_still_refuses_new_scopes():
    w = World(check_scope=False)
    resp, _ = w.send(w.secure, attacks.ATTACKS["missing_scope"])
    assert resp["status"] == 403 and w.api.tickets["T-1"]["status"] == "open"
    assert "cannot gain scopes" in w.secure.log[-1]["reason"]


def test_without_audience_check_the_exchange_refuses_foreign_tokens():
    w = World(check_audience=False)
    resp, _ = w.send(w.secure, attacks.ATTACKS["wrong_audience_replay"])
    assert resp["status"] == 403 and w.api.tickets["T-1"]["status"] == "open"
    assert "not issued to this actor" in w.secure.log[-1]["reason"]


def test_without_expiry_check_the_exchange_refuses_expired_tokens():
    w = World(check_expiry=False)
    resp, _ = w.send(w.secure, attacks.ATTACKS["expired_token"])
    assert resp["status"] == 403


def test_passthrough_fails_when_the_downstream_checks_audience():
    """Lab switch: forward the user's token. A downstream API that checks 'aud' refuses it."""
    w = World(exchange_tokens=False)
    resp, _ = w.send(w.secure, attacks.BENIGN)
    assert resp["status"] == 403
    assert "invalid token for tickets-api" in w.secure.log[-1]["reason"]


def test_per_user_token_means_downstream_enforces_ownership():
    """Even a valid, in-scope, correctly-audienced request for Bob's ticket is refused downstream."""
    w = World()
    resp, _ = w.send(w.secure, attacks.ATTACKS["cross_user_read"])
    assert resp["status"] == 403 and "not your ticket" in w.secure.log[-1]["reason"]


# ---------- Part 4: the authorization server (PKCE + resource indicators) -------------------

def _start_flow(auth, resource=authmod.DOCS_MCP):
    verifier = secrets.token_urlsafe(48)
    code = auth.authorize(client_id="desktop-host", user="alice", code_challenge=authmod.pkce_challenge(verifier),
                          code_challenge_method="S256", resource=resource, scope="tickets:read")
    return verifier, code


def test_pkce_flow_issues_a_token_bound_to_the_requested_resource():
    auth = authmod.AuthorizationServer(now=lambda: NOW)
    verifier, code = _start_flow(auth)
    token = auth.token(code=code, code_verifier=verifier, client_id="desktop-host", resource=authmod.DOCS_MCP)
    assert auth.introspect(token, audience=authmod.DOCS_MCP)["sub"] == "alice"
    assert auth.introspect(token, audience=authmod.TICKETS_API) is None


def test_stolen_code_without_verifier_is_useless():
    auth = authmod.AuthorizationServer(now=lambda: NOW)
    _, code = _start_flow(auth)
    with pytest.raises(authmod.OAuthError, match="PKCE"):
        auth.token(code=code, code_verifier="guess", client_id="desktop-host", resource=authmod.DOCS_MCP)


def test_code_is_single_use():
    auth = authmod.AuthorizationServer(now=lambda: NOW)
    verifier, code = _start_flow(auth)
    auth.token(code=code, code_verifier=verifier, client_id="desktop-host", resource=authmod.DOCS_MCP)
    with pytest.raises(authmod.OAuthError):
        auth.token(code=code, code_verifier=verifier, client_id="desktop-host", resource=authmod.DOCS_MCP)


def test_resource_cannot_be_swapped_at_the_token_endpoint():
    auth = authmod.AuthorizationServer(now=lambda: NOW)
    verifier, code = _start_flow(auth)
    with pytest.raises(authmod.OAuthError, match="invalid_target"):
        auth.token(code=code, code_verifier=verifier, client_id="desktop-host", resource=authmod.TICKETS_API)


def test_plain_pkce_is_refused():
    auth = authmod.AuthorizationServer(now=lambda: NOW)
    with pytest.raises(authmod.OAuthError):
        auth.authorize(client_id="c", user="alice", code_challenge="x", code_challenge_method="plain",
                       resource=authmod.DOCS_MCP, scope="tickets:read")
