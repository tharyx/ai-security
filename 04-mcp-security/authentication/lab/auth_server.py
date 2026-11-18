"""The trusted pieces around the MCP server: an authorization server and a downstream API.

* ``AuthorizationServer`` issues JWT-like tokens signed with HMAC-SHA256 (stdlib only).
  It supports the OAuth 2.1 authorization-code flow with PKCE (S256), resource
  indicators (RFC 8707) that bind a token to one audience, token exchange
  (RFC 8693) and introspection (RFC 7662-style).
* ``TicketsAPI`` is the downstream API the MCP server calls. It holds two users'
  tickets (with canaries) and still accepts a legacy shared admin API key.

Lab simplification: real deployments sign tokens with an *asymmetric* key (RS256 or
ES256) and publish the public key (JWKS). Resource servers can then verify tokens
but can never mint them. HMAC is used here only so the lab needs no extra packages.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from aisec_lab import make_canary

ISSUER = "https://auth.acme.example"
DOCS_MCP = "https://docs-mcp.acme.example"          # our MCP server (an OAuth resource server)
CALENDAR_MCP = "https://calendar-mcp.acme.example"  # some other MCP server
TICKETS_API = "https://tickets-api.acme.example"    # the downstream API

ADMIN_API_KEY = make_canary("CANARY-ADMIN-KEY")     # the shared "god mode" key (a canary)


# ---------------------------------------------------------------------------------
# Token format: base64url(header) . base64url(claims) . base64url(HMAC-SHA256)
# ---------------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(header: dict[str, Any], claims: dict[str, Any], key: bytes) -> str:
    head = b64url(json.dumps(header, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    mac = hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64url(mac)}"


def forge_unsigned(claims: dict[str, Any]) -> str:
    """What an attacker can build with no key at all: alg "none" and an empty signature."""
    head = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    return f"{head}.{b64url(json.dumps(claims).encode())}."


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


class OAuthError(Exception):
    pass


@dataclass
class AuthorizationServer:
    issuer: str = ISSUER
    now: Callable[[], float] = time.time
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _codes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def metadata(self) -> dict[str, Any]:
        """Authorization server metadata (RFC 8414), found by the client via the MCP server's metadata."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token",
                                      "urn:ietf:params:oauth:grant-type:token-exchange"],
        }

    def mint(self, sub: str, aud: str | list[str], scope: str, ttl: int = 300, **extra: Any) -> str:
        now = int(self.now())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "scope": scope,
                  "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8), **extra}
        return sign({"alg": "HS256", "typ": "JWT"}, claims, self.key)

    def verify(self, token: str) -> dict[str, Any] | None:
        """Signature, algorithm, issuer and expiry. Audience is checked by the caller."""
        try:
            head, body, mac = token.split(".")
            header = json.loads(b64url_decode(head))
            claims = json.loads(b64url_decode(body))
        except (ValueError, json.JSONDecodeError):
            return None
        expected = hmac.new(self.key, f"{head}.{body}".encode(), hashlib.sha256).digest()
        if header.get("alg") != "HS256" or not hmac.compare_digest(expected, b64url_decode(mac)):
            return None
        if claims.get("iss") != self.issuer or claims.get("exp", 0) <= self.now():
            return None
        return claims

    # --- OAuth 2.1 authorization code + PKCE + resource indicator ------------------------
    def authorize(self, *, client_id: str, user: str, code_challenge: str, code_challenge_method: str,
                  resource: str, scope: str) -> str:
        if code_challenge_method != "S256":
            raise OAuthError("only S256 PKCE is accepted")
        code = secrets.token_urlsafe(16)
        self._codes[code] = {"client_id": client_id, "user": user, "challenge": code_challenge,
                             "resource": resource, "scope": scope}
        return code

    def token(self, *, code: str, code_verifier: str, client_id: str, resource: str) -> str:
        grant = self._codes.pop(code, None)  # single use
        if grant is None or grant["client_id"] != client_id:
            raise OAuthError("invalid_grant")
        if not hmac.compare_digest(pkce_challenge(code_verifier), grant["challenge"]):
            raise OAuthError("invalid_grant: PKCE verifier does not match")
        if resource != grant["resource"]:
            raise OAuthError("invalid_target: resource differs from the authorization request")
        return self.mint(grant["user"], resource, grant["scope"], client_id=client_id)

    # --- RFC 8693 token exchange ------------------------------------------------------------
    def exchange(self, *, subject_token: str, actor: str, audience: str, scope: str) -> str:
        claims = self.verify(subject_token)
        if claims is None or claims.get("aud") != actor:
            raise OAuthError("invalid_grant: subject token was not issued to this actor")
        if not set(scope.split()) <= set(claims["scope"].split()):
            raise OAuthError("invalid_scope: cannot gain scopes in an exchange")
        return self.mint(claims["sub"], audience, scope, ttl=60, act={"sub": actor})

    # --- RFC 7662-style introspection (used by the downstream API) ------------------------
    def introspect(self, token: str, *, audience: str) -> dict[str, Any] | None:
        claims = self.verify(token)
        if claims is None:
            return None
        aud = claims.get("aud")
        if audience not in (aud if isinstance(aud, list) else [aud]):
            return None
        return claims


class TicketsAPI:
    """The downstream API. It enforces ownership for bearer tokens, but the legacy admin key sees all."""

    def __init__(self, auth: AuthorizationServer) -> None:
        self.auth = auth
        self.tickets = {
            "T-1": {"owner": "alice", "text": "Laptop battery swollen.", "status": "open"},
            "T-2": {"owner": "bob", "text": f"Payroll correction. {make_canary('CANARY-BOB')}", "status": "open"},
        }
        self.received: list[dict[str, Any]] = []  # every credential presented to this API

    def _caller(self, bearer: str | None, api_key: str | None, need: str) -> str | None:
        """Return the user the call is for, or None for the admin key. Raise if not allowed."""
        self.received.append({"bearer": bearer, "api_key": api_key})
        if api_key is not None:
            if hmac.compare_digest(api_key, ADMIN_API_KEY):
                return None  # the shared key: no user, no limits
            raise PermissionError("bad api key")
        claims = self.auth.introspect(bearer or "", audience=TICKETS_API)
        if claims is None:
            raise PermissionError("invalid token for tickets-api")
        if need not in claims["scope"].split():
            raise PermissionError(f"missing scope {need}")
        return claims["sub"]

    def get_ticket(self, ticket_id: str, *, bearer: str | None = None, api_key: str | None = None) -> dict:
        user = self._caller(bearer, api_key, "tickets:read")
        ticket = self.tickets[ticket_id]
        if user is not None and ticket["owner"] != user:
            raise PermissionError("not your ticket")
        return {"id": ticket_id, **ticket}

    def list_tickets(self, *, bearer: str | None = None, api_key: str | None = None) -> list[str]:
        user = self._caller(bearer, api_key, "tickets:read")
        return [tid for tid, t in self.tickets.items() if user is None or t["owner"] == user]

    def close_ticket(self, ticket_id: str, *, bearer: str | None = None, api_key: str | None = None) -> str:
        user = self._caller(bearer, api_key, "tickets:write")
        ticket = self.tickets[ticket_id]
        if user is not None and ticket["owner"] != user:
            raise PermissionError("not your ticket")
        ticket["status"] = "closed"
        return f"{ticket_id} closed"
