"""The same docs-mcp server, rebuilt as a proper OAuth resource server.

Each layer can be switched off so you can prove which layer stopped which attack:

    L1  Strict token validation: algorithm allowlist (never "none"), signature, issuer.
    L2  Audience binding: the token's "aud" must be exactly this server (RFC 8707 /
        RFC 9728). A token minted for another service is rejected, even if valid there.
    L3  Expiry: short-lived tokens; expired ones are rejected.
    L4  Scopes per tool: 403 insufficient_scope when the token lacks the tool's scope.
    L5  No passthrough: for the downstream call, exchange the user's token for a new,
        narrow, short-lived token for the downstream audience (RFC 8693). The user's
        identity travels with it, so the downstream API enforces per-user access.
        There is no shared admin key in this server at all.
    L6  Hygiene: 401 responses point clients to the protected resource metadata;
        tokens in query strings are refused; logs hold a token fingerprint, never the token.

L1-L5 are deterministic checks. They also back each other up: switch one off and
the token exchange or the downstream API still refuses (see the tests).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Callable

ISSUER = "https://auth.acme.example"
RESOURCE = "https://docs-mcp.acme.example"
DOWNSTREAM = "https://tickets-api.acme.example"
METADATA_URL = f"{RESOURCE}/.well-known/oauth-protected-resource"

TOOL_SCOPES = {"get_ticket": "tickets:read", "list_my_tickets": "tickets:read", "close_ticket": "tickets:write"}


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(token: str) -> str:
    """Safe to log: lets you correlate requests without storing a usable token."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


class SecureDocsMCPServer:
    def __init__(
        self,
        signing_key: bytes,
        tickets_api: Any,
        exchange: Callable[..., str],
        *,
        now: Callable[[], float] = time.time,
        check_audience: bool = True,
        check_expiry: bool = True,
        check_scope: bool = True,
        exchange_tokens: bool = True,
    ) -> None:
        self.key = signing_key          # lab only: in production, the AS's *public* key (JWKS)
        self.tickets = tickets_api
        self.exchange = exchange        # calls the authorization server's token endpoint
        self.now = now
        self.check_audience = check_audience
        self.check_expiry = check_expiry
        self.check_scope = check_scope
        self.exchange_tokens = exchange_tokens
        self.log: list[dict[str, Any]] = []

    # --- discovery (RFC 9728) -------------------------------------------------------------
    @staticmethod
    def protected_resource_metadata() -> dict[str, Any]:
        """Served at /.well-known/oauth-protected-resource. Tells clients where to get tokens."""
        return {
            "resource": RESOURCE,
            "authorization_servers": [ISSUER],
            "scopes_supported": sorted(set(TOOL_SCOPES.values())),
            "bearer_methods_supported": ["header"],
        }

    @staticmethod
    def _unauthorized(reason: str) -> dict[str, Any]:
        return {"status": 401, "headers": {"WWW-Authenticate": f'Bearer resource_metadata="{METADATA_URL}"'},
                "body": {"error": "invalid_token", "error_description": reason}}

    @staticmethod
    def _forbidden(reason: str, scope: str = "") -> dict[str, Any]:
        www = f'Bearer error="insufficient_scope", scope="{scope}"' if scope else 'Bearer error="access_denied"'
        return {"status": 403, "headers": {"WWW-Authenticate": www}, "body": {"error": reason}}

    # --- L1 + L2 + L3 ---------------------------------------------------------------------------
    def validate(self, token: str) -> tuple[dict[str, Any] | None, str]:
        try:
            head, body, mac = token.split(".")
            header, claims = json.loads(_b64d(head)), json.loads(_b64d(body))
        except (ValueError, json.JSONDecodeError):
            return None, "malformed token"
        if header.get("alg") != "HS256":  # allowlist chosen by the server, never by the token
            return None, f"algorithm {header.get('alg')!r} not allowed"
        expected = hmac.new(self.key, f"{head}.{body}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(mac or "")):
            return None, "bad signature"
        if claims.get("iss") != ISSUER:
            return None, "wrong issuer"
        if self.check_audience and claims.get("aud") != RESOURCE:
            return None, "token was not issued for this server (audience mismatch)"
        if self.check_expiry and claims.get("exp", 0) <= self.now():
            return None, "token expired"
        return claims, "ok"

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        cid = uuid.uuid4().hex[:12]
        if "access_token" in request.get("query", {}):
            self._log(cid, None, "?", "deny", "token in URL query string")
            return {"status": 400, "headers": {}, "body": {"error": "tokens are not accepted in the URL"}}
        auth = request.get("headers", {}).get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._log(cid, None, "?", "deny", "no token")
            return self._unauthorized("missing bearer token")
        token = auth.removeprefix("Bearer ")
        claims, reason = self.validate(token)
        params = (request.get("body") or {}).get("params", {})
        tool, args = params.get("name", ""), params.get("arguments", {})
        if claims is None:
            self._log(cid, token, tool, "deny", reason)
            return self._unauthorized(reason)

        # --- L4: scope per tool ---
        needed = TOOL_SCOPES.get(tool)
        if needed is None:
            return {"status": 400, "headers": {}, "body": {"error": "unknown tool"}}
        if self.check_scope and needed not in str(claims.get("scope", "")).split():
            self._log(cid, token, tool, "deny", f"missing scope {needed}", claims.get("sub"))
            return self._forbidden("insufficient_scope", needed)

        # --- L5: a new token for the downstream audience, never the user's own token ---
        if self.exchange_tokens:
            try:
                downstream_token = self.exchange(subject_token=token, actor=RESOURCE,
                                                 audience=DOWNSTREAM, scope=needed)
            except Exception as exc:  # the authorization server said no
                self._log(cid, token, tool, "deny", f"token exchange refused: {exc}", claims.get("sub"))
                return self._forbidden("token exchange refused")
        else:
            downstream_token = token  # lab switch only: shows what passthrough would do

        try:
            if tool == "get_ticket":
                result: Any = self.tickets.get_ticket(str(args.get("ticket_id", "")), bearer=downstream_token)
            elif tool == "close_ticket":
                result = self.tickets.close_ticket(str(args.get("ticket_id", "")), bearer=downstream_token)
            else:
                result = self.tickets.list_tickets(bearer=downstream_token)
        except (PermissionError, KeyError) as exc:
            self._log(cid, token, tool, "deny", f"downstream denied: {exc}", claims.get("sub"))
            return self._forbidden("downstream denied the request")
        self._log(cid, token, tool, "allow", "ok", claims.get("sub"))
        return {"status": 200, "headers": {}, "body": {"result": result}}

    def _log(self, cid: str, token: str | None, tool: str, decision: str, reason: str, sub: Any = None) -> None:
        self.log.append({"correlation_id": cid, "sub": sub, "tool": tool, "decision": decision,
                         "reason": reason, "token_fp": fingerprint(token) if token else None})
