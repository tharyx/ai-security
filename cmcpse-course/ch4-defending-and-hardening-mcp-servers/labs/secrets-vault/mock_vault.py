"""A mock HashiCorp-Vault-like server (in-process HTTP on 127.0.0.1) for the secrets lab.

It imitates the SHAPE of a few Vault HTTP API calls so the MCP server code looks like real client code.
It is NOT Vault: no storage encryption, no real policies language, no audit device. Verify the real API at
developer.hashicorp.com/vault/api-docs.

    POST /v1/auth/approle/login        {role_id, secret_id}        -> client token with TTL and policies
    GET  /v1/kv/data/<path>            X-Vault-Token               -> static secret (versioned)
    GET  /v1/database/creds/<role>     X-Vault-Token               -> DYNAMIC username/password with a lease
    PUT  /v1/sys/leases/renew          {lease_id, increment}       -> extend a lease
    PUT  /v1/sys/leases/revoke         {lease_id}                  -> revoke now (credentials stop working)

Server-side helpers for tests: rotate_kv(), expire(), db_login_ok(), partner_key_ok().
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


class MockVault:
    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self.now = now
        self.approle: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, list[str]]] = {}
        self.kv: dict[str, dict[str, Any]] = {}
        self.kv_version: dict[str, int] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.leases: dict[str, dict[str, Any]] = {}
        self.db_users: dict[str, str] = {}          # username -> password (the "database" state)
        self.requests: list[tuple[str, str]] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ configuration
    def add_approle(self, role_id: str, secret_id: str, policies: list[str], token_ttl: int = 300, secret_id_uses: int = 0) -> None:
        self.approle[role_id] = {"secret_id": secret_id, "policies": policies, "ttl": token_ttl, "uses_left": secret_id_uses}

    def add_policy(self, name: str, read_kv: list[str] = (), db_roles: list[str] = ()) -> None:
        self.policies[name] = {"kv": list(read_kv), "db": list(db_roles)}

    def put_kv(self, path: str, data: dict[str, Any]) -> None:
        self.kv[path] = dict(data)
        self.kv_version[path] = self.kv_version.get(path, 0) + 1

    rotate_kv = put_kv   # rotation = write a new version; clients pick it up on the next read

    # ------------------------------------------------------------------ checks the "downstream systems" use
    def db_login_ok(self, user: str, password: str) -> bool:
        lease = next((l for l in self.leases.values() if l.get("user") == user), None)
        return self.db_users.get(user) == password and bool(lease) and lease["expires"] > self.now() and not lease["revoked"]

    def partner_key_ok(self, path: str, key: str) -> bool:
        return self.kv.get(path, {}).get("api_key") == key

    # ------------------------------------------------------------------ request handling
    def _token_ok(self, token: str | None) -> dict | None:
        t = self.tokens.get(token or "")
        return t if t and t["expires"] > self.now() else None

    def _allowed(self, tok: dict, kind: str, name: str) -> bool:
        return any(name in self.policies.get(p, {}).get(kind, []) for p in tok["policies"])

    def handle(self, method: str, path: str, token: str | None, body: dict) -> tuple[int, dict]:
        self.requests.append((method, path))
        if method == "POST" and path == "/v1/auth/approle/login":
            role = self.approle.get(body.get("role_id", ""))
            if not role or not secrets.compare_digest(role["secret_id"], str(body.get("secret_id", ""))):
                return 403, {"errors": ["invalid role or secret ID"]}
            if role["uses_left"] == 1:
                role["secret_id"] = secrets.token_hex(16)     # a one-time secret ID is burned after use
            elif role["uses_left"] > 1:
                role["uses_left"] -= 1
            tok = "hvs." + secrets.token_urlsafe(20)
            self.tokens[tok] = {"policies": role["policies"], "expires": self.now() + role["ttl"]}
            return 200, {"auth": {"client_token": tok, "lease_duration": role["ttl"], "policies": role["policies"]}}
        tok = self._token_ok(token)
        if not tok:
            return 403, {"errors": ["permission denied"]}
        if method == "GET" and path.startswith("/v1/kv/data/"):
            name = path[len("/v1/kv/data/"):]
            if not self._allowed(tok, "kv", name):
                return 403, {"errors": ["permission denied"]}
            if name not in self.kv:
                return 404, {"errors": []}
            return 200, {"data": {"data": dict(self.kv[name]), "metadata": {"version": self.kv_version[name]}}}
        if method == "GET" and path.startswith("/v1/database/creds/"):
            role = path[len("/v1/database/creds/"):]
            if not self._allowed(tok, "db", role):
                return 403, {"errors": ["permission denied"]}
            user, pw, lease_id = "v-" + secrets.token_hex(4), secrets.token_urlsafe(18), f"database/creds/{role}/" + secrets.token_hex(6)
            ttl = 120
            self.db_users[user] = pw
            self.leases[lease_id] = {"user": user, "expires": self.now() + ttl, "revoked": False, "ttl": ttl}
            return 200, {"lease_id": lease_id, "lease_duration": ttl, "renewable": True, "data": {"username": user, "password": pw}}
        if method == "PUT" and path == "/v1/sys/leases/renew":
            lease = self.leases.get(body.get("lease_id", ""))
            if not lease or lease["revoked"]:
                return 400, {"errors": ["lease not found"]}
            lease["expires"] = self.now() + int(body.get("increment", lease["ttl"]))
            return 200, {"lease_id": body["lease_id"], "lease_duration": int(body.get("increment", lease["ttl"]))}
        if method == "PUT" and path == "/v1/sys/leases/revoke":
            lease = self.leases.get(body.get("lease_id", ""))
            if lease:
                lease["revoked"] = True
            return 204, {}
        return 404, {"errors": ["unsupported path"]}

    # ------------------------------------------------------------------ HTTP plumbing
    def start(self) -> str:
        vault = self

        class Handler(BaseHTTPRequestHandler):
            def _do(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
                status, payload = vault.handle(method, self.path, self.headers.get("X-Vault-Token"), body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if status != 204:
                    self.wfile.write(data)

            def do_GET(self): self._do("GET")      # noqa: E704
            def do_POST(self): self._do("POST")    # noqa: E704
            def do_PUT(self): self._do("PUT")      # noqa: E704
            def log_message(self, *args): pass     # keep test output quiet; noqa: E704

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)   # loopback only, free port
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
