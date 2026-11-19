"""Defending OAuth scopes on an MCP server: scope checks per tool, audience binding, over-scope rejection.

Stdlib only. Tokens are JWT-like: base64url(header).base64url(claims).HMAC-SHA256 (like 04-mcp-security/authentication).
Lab simplification: real systems sign with an asymmetric key (RS256/ES256) and publish a JWKS; the resource
server then can verify tokens but never mint them. Here one shared HMAC key keeps the lab dependency-free.

Checks the MCP server performs, in this order (each has its own error so you can see which one fired):
    1. signature and format             -> 401 invalid_token
    2. expiry and not-before            -> 401 invalid_token
    3. issuer                           -> 401 invalid_token
    4. AUDIENCE binding (RFC 8707)      -> 401 invalid_token  (token minted for another resource server)
    5. over-scoped token                -> 403 over_scoped    (wildcards, or more than the client may hold)
    6. per-tool scope check             -> 403 insufficient_scope (names the missing scope)
Tools not listed in the policy are denied by default.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

ISSUER = "https://auth.acme.example"
AUDIENCE = "https://notes-mcp.acme.example"
OTHER_AUDIENCE = "https://calendar-mcp.acme.example"

FORBIDDEN_SCOPES = {"*", "admin", "admin:*", "all"}


class AuthError(Exception):
    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{status} {code} {detail}".strip())
        self.status, self.code, self.detail = status, code, detail


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class Issuer:
    """A toy authorization server. It mints whatever it is asked to (like a misconfigured real one)."""
    key: bytes
    issuer: str = ISSUER
    now: Callable[[], float] = time.time

    def mint(self, sub: str, client_id: str, scopes: list[str], aud: str | list[str], ttl: int = 300) -> str:
        claims = {"iss": self.issuer, "sub": sub, "client_id": client_id, "scope": " ".join(scopes),
                  "aud": aud, "iat": int(self.now()), "exp": int(self.now()) + ttl}
        head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = _b64(json.dumps(claims).encode())
        mac = hmac.new(self.key, f"{head}.{body}".encode(), hashlib.sha256).digest()
        return f"{head}.{body}.{_b64(mac)}"


@dataclass
class Claims:
    sub: str
    client_id: str
    scopes: frozenset[str]
    aud: tuple[str, ...]


@dataclass
class ToolPolicy:
    """tool name -> scopes needed (all of them). Tools not listed are denied."""
    tool_scopes: dict[str, frozenset[str]]
    client_max_scopes: dict[str, frozenset[str]]   # what each registered client may ever hold

    @classmethod
    def default(cls) -> "ToolPolicy":
        return cls(
            tool_scopes={"notes.read": frozenset({"notes:read"}),
                         "notes.write": frozenset({"notes:write"}),
                         "notes.delete": frozenset({"notes:write", "notes:delete"})},
            client_max_scopes={"reader-app": frozenset({"notes:read"}),
                               "editor-app": frozenset({"notes:read", "notes:write"}),
                               "admin-app": frozenset({"notes:read", "notes:write", "notes:delete"})})


@dataclass
class ScopedServer:
    key: bytes
    policy: ToolPolicy = field(default_factory=ToolPolicy.default)
    audience: str = AUDIENCE
    issuer: str = ISSUER
    now: Callable[[], float] = time.time
    check_audience: bool = True       # switch off to see the confused-deputy failure
    check_over_scope: bool = True
    notes: dict[str, str] = field(default_factory=lambda: {"n1": "hello"})
    log: list[dict[str, Any]] = field(default_factory=list)

    # ---- token validation
    def verify(self, token: str) -> Claims:
        try:
            head, body, sig = token.split(".")
            mac = hmac.new(self.key, f"{head}.{body}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(_unb64(sig), mac):
                raise AuthError(401, "invalid_token", "bad signature")
            claims = json.loads(_unb64(body))
        except AuthError:
            raise
        except Exception as exc:  # malformed token of any kind
            raise AuthError(401, "invalid_token", "malformed") from exc
        t = self.now()
        if claims.get("exp", 0) <= t:
            raise AuthError(401, "invalid_token", "expired")
        if claims.get("nbf", 0) > t:
            raise AuthError(401, "invalid_token", "not yet valid")
        if claims.get("iss") != self.issuer:
            raise AuthError(401, "invalid_token", "wrong issuer")
        aud = claims.get("aud", [])
        aud = (aud,) if isinstance(aud, str) else tuple(aud)
        if self.check_audience and self.audience not in aud:
            raise AuthError(401, "invalid_token", "wrong audience")
        scopes = frozenset(str(claims.get("scope", "")).split())
        client_id = str(claims.get("client_id", ""))
        if self.check_over_scope:
            bad = scopes & FORBIDDEN_SCOPES
            allowed = self.policy.client_max_scopes.get(client_id)
            if bad or allowed is None or not scopes <= allowed:
                extra = sorted(bad or (scopes - (allowed or frozenset())))
                raise AuthError(403, "over_scoped", f"token holds scopes it should not: {extra}")
        return Claims(str(claims.get("sub", "")), client_id, scopes, aud)

    def required(self, tool: str) -> frozenset[str]:
        if tool not in self.policy.tool_scopes:
            raise AuthError(403, "tool_not_allowed", tool)
        return self.policy.tool_scopes[tool]

    # ---- MCP methods
    def handle(self, token: str | None, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return {"result": ...} or {"error": {"status", "code", "detail", "www_authenticate"?}}."""
        params = params or {}
        try:
            if not token:
                raise AuthError(401, "invalid_token", "missing token")
            claims = self.verify(token)
            if method == "tools/list":
                # Only advertise what this token can call (see also least-privilege-tools lab).
                names = [t for t, need in self.policy.tool_scopes.items() if need <= claims.scopes]
                result: Any = {"tools": [{"name": n} for n in names]}
            elif method == "tools/call":
                tool = params.get("name", "")
                need = self.required(tool)
                missing = need - claims.scopes
                if missing:
                    raise AuthError(403, "insufficient_scope", f"missing {sorted(missing)}")
                result = self._run(tool, params.get("arguments", {}))
            else:
                raise AuthError(404, "method_not_found", method)
            self._audit(claims, method, params, "allow")
            return {"result": result}
        except AuthError as err:
            err_obj = {"status": err.status, "code": err.code, "detail": err.detail}
            if err.status == 401:
                err_obj["www_authenticate"] = f'Bearer resource_metadata="{self.audience}/.well-known/oauth-protected-resource"'
            if err.code == "insufficient_scope":
                err_obj["www_authenticate"] = f'Bearer error="insufficient_scope", scope="{" ".join(sorted(self.policy.tool_scopes.get(params.get("name", ""), [])))}"'
            self.log.append({"decision": "deny", "method": method, "code": err.code})
            return {"error": err_obj}

    def _audit(self, claims: Claims, method: str, params: dict, decision: str) -> None:
        self.log.append({"decision": decision, "sub": claims.sub, "client_id": claims.client_id,
                         "method": method, "tool": params.get("name")})

    def _run(self, tool: str, args: dict[str, Any]) -> Any:
        if tool == "notes.read":
            return self.notes.get(args.get("id", ""), "")
        if tool == "notes.write":
            self.notes[args["id"]] = args["text"]
            return "ok"
        if tool == "notes.delete":
            return "deleted" if self.notes.pop(args["id"], None) is not None else "missing"
        raise AuthError(404, "tool_not_found", tool)
