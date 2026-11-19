"""An MCP server that gets its secrets from a vault at CALL TIME.

Rules the code follows (each one has a test):
    * No secret in a tool schema or description (tools/list is secret-free).
    * No secret in the process environment (the server is started with only VAULT_ADDR and an AppRole ID,
      and the one-time secret ID is used once, then dropped).
    * Dynamic database credentials with a lease: cached only until shortly before the lease ends, then renewed
      or replaced. A revoked lease or a rotated password is detected (login fails) and the server fetches again once.
    * Static secrets (a partner API key) are read on every call, so rotation takes effect at the next call.
    * Every log line passes through a Redactor that knows the secret values it has handled plus common patterns.
    * Fail closed: if the vault is unreachable, the tool returns a generic error (no secret, no stack trace).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

PATTERNS = [re.compile(p) for p in (r"hvs\.[A-Za-z0-9_-]{8,}", r"(?i)(password|passwd|api[_-]?key|secret|token)\s*[=:]\s*\S+", r"AKIA[0-9A-Z]{16}")]


class VaultError(Exception):
    pass


class Redactor:
    """Replace known secret values and secret-looking patterns. Register values the moment you receive them."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def register(self, *values: str) -> None:
        self._values |= {v for v in values if v and len(v) >= 6}

    def __call__(self, text: str) -> str:
        for v in sorted(self._values, key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        for p in PATTERNS:
            text = p.sub(lambda m: m.group(1) + "=[REDACTED]" if m.lastindex else "[REDACTED]", text)
        return text


class VaultClient:
    """Tiny HTTP client for the mock vault (same calls hvac makes against a real Vault)."""

    def __init__(self, addr: str, role_id: str, secret_id: str | None, redact: Redactor, now: Callable[[], float] = time.time) -> None:
        self.addr, self.role_id, self._secret_id, self.redact, self.now = addr, role_id, secret_id, redact, now
        self.token: str | None = None
        self.token_expires = 0.0

    def _req(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-Vault-Token"] = self.token or ""
        req = urllib.request.Request(self.addr + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raise VaultError(f"vault returned {exc.code}") from None      # no response body, no headers in the message
        except (urllib.error.URLError, TimeoutError, OSError):
            raise VaultError("vault unreachable") from None

    def login(self) -> None:
        if self._secret_id is None:
            raise VaultError("no secret id available")
        data = self._req("POST", "/v1/auth/approle/login", {"role_id": self.role_id, "secret_id": self._secret_id}, auth=False)
        self.token = data["auth"]["client_token"]
        self.redact.register(self.token)
        self.token_expires = self.now() + data["auth"]["lease_duration"] - 5
        self._secret_id = None                    # never keep the bootstrap secret around after use

    def _ensure(self) -> None:
        if not self.token or self.now() >= self.token_expires:
            self.login()

    def kv(self, path: str) -> dict[str, Any]:
        self._ensure()
        data = self._req("GET", f"/v1/kv/data/{path}")["data"]["data"]
        self.redact.register(*[str(v) for v in data.values()])
        return data

    def db_creds(self, role: str) -> dict[str, Any]:
        self._ensure()
        data = self._req("GET", f"/v1/database/creds/{role}")
        self.redact.register(data["data"]["password"])
        return data

    def revoke(self, lease_id: str) -> None:
        self._ensure()
        self._req("PUT", "/v1/sys/leases/revoke", {"lease_id": lease_id})


@dataclass
class SecretsServer:
    vault: VaultClient
    database: Callable[[str, str], bool]          # (user, password) -> login ok   (the fake downstream database)
    partner_api: Callable[[str], bool]            # (api key) -> accepted          (the fake partner API)
    now: Callable[[], float] = time.time
    log: list[str] = field(default_factory=list)
    _creds: dict[str, Any] | None = None
    _creds_until: float = 0.0
    fetches: int = 0

    TOOLS = [
        {"name": "run_report", "description": "Run the monthly sales report.", "inputSchema": {"type": "object", "properties": {"month": {"type": "string"}}, "required": ["month"], "additionalProperties": False}},
        {"name": "sync_partner", "description": "Push the latest catalogue to the partner.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    ]

    def _log(self, msg: str) -> None:
        self.log.append(self.vault.redact(msg))      # every line is redacted BEFORE it is stored

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        rid, method, params = request.get("id"), request.get("method"), request.get("params") or {}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.TOOLS}}
        if method != "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
        name = params.get("name")
        try:
            text = self._report(params.get("arguments", {})) if name == "run_report" else self._sync() if name == "sync_partner" else None
            if text is None:
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown tool"}}
            self._log(f"tool={name} ok")
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}}
        except VaultError as exc:
            self._log(f"tool={name} failed: {exc}")
            return {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": "Secret backend unavailable. Try again later."}]}}
        except Exception as exc:                                       # never echo raw exception text to the model
            self._log(f"tool={name} error: {exc!r}")
            return {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "content": [{"type": "text", "text": "Internal error."}]}}

    # ------------------------------------------------------------ dynamic database credentials
    def _db_creds(self, force: bool = False) -> dict[str, Any]:
        if force or not self._creds or self.now() >= self._creds_until:
            lease = self.vault.db_creds("reporting")
            self.fetches += 1
            self._creds = lease["data"]
            self._creds_until = self.now() + lease["lease_duration"] * 0.8    # renew early, never at the last second
        return self._creds

    def _report(self, args: dict[str, Any]) -> str:
        for attempt in (0, 1):
            creds = self._db_creds(force=attempt == 1)
            if self.database(creds["username"], creds["password"]):
                return f"report for {args.get('month', '?')} generated as {creds['username']}"
            self._log(f"database login failed for {creds['username']} (attempt {attempt + 1}); credentials may be rotated or revoked")
        raise VaultError("database login failed")

    # ------------------------------------------------------------ static secret read at call time
    def _sync(self) -> str:
        key = self.vault.kv("partner")["api_key"]
        if not self.partner_api(key):
            raise VaultError("partner rejected the key")
        return "catalogue synchronised"
