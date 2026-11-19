"""Confused deputy: a privileged MCP server acts for an attacker using its own, broader authority.

Part 1: ``BillingServer`` holds a service credential that can read every tenant's invoices.
  Vulnerable: it authorises with ITS OWN identity, so any caller can ask for any tenant.
  Defended:   it checks the caller's token (audience, scope, tenant) and the datastore applies the
              caller's tenant as a row filter (on-behalf-of), so even a server bug cannot widen access.

Part 2: ``OAuthProxy`` is the classic MCP variant: a proxy with ONE static upstream client id
  remembers 'the user consented'. A new, attacker-registered client then rides that consent.

All data are canaries; tokens are opaque strings from a toy token service.
"""

from __future__ import annotations

from typing import Any

from aisec_lab import load_lab_module, make_canary

rpc = load_lab_module(__file__, "rpc")

CANARY_ACME = make_canary("CANARY-ACME-INV")
CANARY_GLOBEX = make_canary("CANARY-GLOBEX-INV")
AUDIENCE = "billing-mcp"


class TokenService:
    def __init__(self) -> None:
        self._tokens: dict[str, dict[str, Any]] = {}

    def issue(self, sub: str, tenant: str, scopes: tuple[str, ...], aud: str = AUDIENCE) -> str:
        tok = f"tok-{len(self._tokens)}-{sub}"
        self._tokens[tok] = {"sub": sub, "tenant": tenant, "scopes": list(scopes), "aud": aud}
        return tok

    def introspect(self, tok: str | None) -> dict[str, Any] | None:
        return self._tokens.get(tok or "")


class Datastore:
    """Holds every tenant's data. ``query`` can enforce a row filter for the caller's tenant."""

    def __init__(self) -> None:
        self.rows = {"acme": f"acme invoices: total 120k, ref {CANARY_ACME}", "globex": f"globex invoices: total 900k, ref {CANARY_GLOBEX}"}

    def query(self, tenant: str, *, as_tenant: str | None = None) -> str:
        if as_tenant is not None and as_tenant != tenant:  # on-behalf-of: the DB itself refuses
            raise rpc.ToolError("row-level security: wrong tenant")
        return self.rows[tenant]


class BillingServer(rpc.Server):
    def __init__(self, tokens: TokenService, db: Datastore, *, defended: bool, check_in_server: bool = True) -> None:
        self.tokens, self.db, self.defended, self.check_in_server = tokens, db, defended, check_in_server
        self.audit: list[str] = []
        self._caller: str | None = None
        super().__init__("billing-mcp", "1.0.0", [rpc.Tool(
            "export_invoices", "Export a tenant's invoices.", rpc.schema(tenant={"type": "string"}), self._export)])

    def handle(self, raw: str, token: str | None = None) -> str | None:
        self._caller = token
        return super().handle(raw, None)

    def _export(self, tenant: str) -> str:
        claims = self.tokens.introspect(self._caller)
        if not self.defended:
            # VULN: the server's own broad credential is used; the caller's identity is never compared with the resource.
            self.audit.append(f"export {tenant} (caller unchecked)")
            return self.db.query(tenant)
        if claims is None or claims["aud"] != AUDIENCE:  # also rejects a token minted for another service (passthrough)
            self.audit.append(f"deny {tenant}: invalid token or wrong audience")
            raise rpc.ToolError("forbidden")
        if "invoices:read" not in claims["scopes"]:
            self.audit.append(f"deny {tenant} for {claims['sub']}: missing scope")
            raise rpc.ToolError("forbidden")
        if self.check_in_server and claims["tenant"] != tenant:
            self.audit.append(f"deny {tenant} for {claims['sub']}: tenant mismatch")
            raise rpc.ToolError("forbidden")
        self.audit.append(f"allow {tenant} for {claims['sub']}")
        return self.db.query(tenant, as_tenant=claims["tenant"])


# ---------------------------------------------------------------------------------
# Part 2: OAuth proxy with a static client id
# ---------------------------------------------------------------------------------
class OAuthProxy:
    """Toy MCP OAuth proxy. ``authorize`` returns a redirect URL carrying a code, or 'consent_required'."""

    UPSTREAM_CLIENT_ID = "static-upstream-client"

    def __init__(self, *, per_client_consent: bool) -> None:
        self.per_client_consent = per_client_consent
        self.clients: dict[str, str] = {}   # dynamically registered client_id -> exact redirect_uri
        self.consented: set[tuple[str, ...]] = set()
        self.codes_issued: list[tuple[str, str]] = []

    def register(self, client_id: str, redirect_uri: str) -> None:
        self.clients[client_id] = redirect_uri

    def _key(self, user: str, client_id: str, redirect_uri: str) -> tuple[str, ...]:
        if self.per_client_consent:
            return (user, client_id, redirect_uri)
        return (user, self.UPSTREAM_CLIENT_ID)  # VULN: consent is remembered per upstream id, shared by every client

    def user_consents(self, user: str, client_id: str, redirect_uri: str) -> None:
        self.consented.add(self._key(user, client_id, redirect_uri))

    def authorize(self, user: str, client_id: str, redirect_uri: str) -> str:
        if self.per_client_consent and self.clients.get(client_id) != redirect_uri:
            return "error: redirect_uri does not match the registered one"
        if self._key(user, client_id, redirect_uri) not in self.consented:
            return "consent_required"
        self.codes_issued.append((user, redirect_uri))
        return f"{redirect_uri}?code=CODE-{len(self.codes_issued)}"
