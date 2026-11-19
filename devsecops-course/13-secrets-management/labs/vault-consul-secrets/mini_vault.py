"""MiniVault: a Vault-LIKE secrets server for teaching (offline, in-process, optional 127.0.0.1 HTTP wrapper).

It imitates the SHAPE of a few HashiCorp Vault / OpenBao HTTP API calls so client code looks real:

  auth     token (root + created child tokens), AppRole login, renew-self, revoke-self, lookup-self
  policies path ACLs: {"secret/data/app/*": ["read"]}  (real Vault uses HCL policy files; verify)
  kv v2    secret/data/<p> (versions, cas, soft delete, undelete, destroy), secret/metadata/<p>
  transit  encryption as a service: the key is created and kept SERVER-SIDE and is never returned
  database dynamic credentials with leases: database/creds/<role>, sys/leases/renew|revoke
  storage  a Consul-like KV backend or a Raft-like integrated store; Vault encrypts BEFORE storing
  seal     sys/seal, sys/unseal (a single unseal key here; real Vault uses Shamir shares or auto-unseal)
  audit    every request is logged with an HMAC'd token accessor and NEVER with secret values

!!! TEACHING ONLY, NOT REAL CRYPTO !!!
The cipher below is an HMAC-SHA256 counter keystream with an HMAC tag, built from the standard
library so the lab needs no dependencies. It shows the idea (authenticated encryption, nonce,
key versions). Do not use it for anything real: use AES-GCM or ChaCha20-Poly1305 from a vetted
library, or Vault/OpenBao itself.

Verify the real API at developer.hashicorp.com/vault/api-docs (or the OpenBao docs).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


class VaultError(Exception):
    pass


# ---------------------------------------------------------------- teaching-only authenticated cipher
def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def seal_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """nonce(16) | tag(32) | ciphertext. TEACHING ONLY."""
    enc_key = hmac.new(key, b"enc", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"mac", hashlib.sha256).digest()
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    tag = hmac.new(mac_key, nonce + aad + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def open_bytes(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 48:
        raise VaultError("ciphertext too short")
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    enc_key = hmac.new(key, b"enc", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"mac", hashlib.sha256).digest()
    if not hmac.compare_digest(tag, hmac.new(mac_key, nonce + aad + ct, hashlib.sha256).digest()):
        raise VaultError("authentication failed (wrong key, wrong context or tampered data)")
    return bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct))))


b64e = lambda b: base64.b64encode(b).decode()  # noqa: E731
b64d = lambda s: base64.b64decode(s.encode())  # noqa: E731


# ---------------------------------------------------------------- storage backends
class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class _MemoryBackend:
    """Common behaviour of both backends: an ordered KV store with a modify index."""

    kind = "memory"

    def __init__(self) -> None:
        self._data: dict[str, tuple[bytes, int]] = {}
        self._index = 0
        self.operations: list[tuple[str, str]] = []  # what the storage layer could observe

    def put(self, key: str, value: bytes, cas: int | None = None) -> bool:
        self.operations.append(("put", key))
        current = self._data.get(key)
        if cas is not None and ((cas == 0 and current) or (cas != 0 and (not current or current[1] != cas))):
            return False
        self._index += 1
        self._data[key] = (value, self._index)
        return True

    def get(self, key: str) -> tuple[bytes, int] | None:
        self.operations.append(("get", key))
        return self._data.get(key)

    def delete(self, key: str) -> None:
        self.operations.append(("delete", key))
        self._data.pop(key, None)

    def list(self, prefix: str) -> list[str]:
        return sorted(k for k in self._data if k.startswith(prefix))

    def raw_dump(self) -> dict[str, bytes]:
        """What an attacker with the storage backend (and no unseal key) would get."""
        return {k: v for k, (v, _i) in self._data.items()}


class ConsulLikeKV(_MemoryBackend):
    """Imitates Consul's KV store: keys under a path prefix, ModifyIndex, check-and-set (cas).
    Vault stores ONLY ciphertext here. Consul is less common now than integrated storage; verify."""

    kind = "consul"


class RaftIntegratedStorage(_MemoryBackend):
    """Imitates Vault integrated storage (Raft): data lives on the Vault nodes, no external service."""

    kind = "raft"


class FakeDatabase:
    """A fake database whose users Vault creates and drops (dynamic secrets)."""

    def __init__(self) -> None:
        self.users: dict[str, str] = {"app_static": "static-password-CANARY"}

    def create_user(self, name: str, password: str) -> None:
        self.users[name] = password

    def drop_user(self, name: str) -> None:
        self.users.pop(name, None)

    def login_ok(self, name: str, password: str) -> bool:
        return name in self.users and hmac.compare_digest(self.users[name], password)


# ---------------------------------------------------------------- the server
CAPS = {"create", "read", "update", "delete", "list", "deny"}
ANY_TOKEN_PATHS = {"auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self"}


def path_matches(pattern: str, path: str) -> bool:
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    pp, ap = pattern.split("/"), path.split("/")
    return len(pp) == len(ap) and all(a == "+" or a == b for a, b in zip(pp, ap))


class MiniVault:
    def __init__(self, backend: _MemoryBackend | None = None, clock: Clock | None = None) -> None:
        self.backend = backend or ConsulLikeKV()
        self.clock = clock or Clock()
        self.sealed = True
        self.initialized = False
        self._barrier: bytes | None = None
        self.tokens: dict[str, dict[str, Any]] = {}
        self.leases: dict[str, dict[str, Any]] = {}
        self.database: FakeDatabase | None = None
        self.audit_log: list[dict[str, Any]] = []
        self._audit_salt = secrets.token_bytes(16)
        self._secret_ids: dict[str, dict[str, Any]] = {}

    # ----- encrypted storage ("barrier")
    def _put(self, path: str, doc: Any, cas: int | None = None) -> bool:
        assert self._barrier is not None
        blob = seal_bytes(self._barrier, json.dumps(doc).encode(), aad=path.encode())
        return self.backend.put("vault/" + path, blob, cas)

    def _get(self, path: str) -> Any | None:
        assert self._barrier is not None
        got = self.backend.get("vault/" + path)
        if got is None:
            return None
        return json.loads(open_bytes(self._barrier, got[0], aad=path.encode()))

    # ----- lifecycle
    def initialize(self) -> dict[str, str]:
        if self.initialized:
            raise VaultError("already initialized")
        self._barrier = secrets.token_bytes(32)
        unseal_key = secrets.token_bytes(32)
        self.backend.put("vault/core/keyring", seal_bytes(unseal_key, self._barrier))
        self.initialized, self.sealed = True, False
        root = self._new_token(["root"], ttl=None)
        return {"root_token": root, "unseal_key": b64e(unseal_key)}

    def seal(self) -> None:
        self._barrier, self.sealed = None, True

    def unseal(self, unseal_key_b64: str) -> bool:
        blob = self.backend.get("vault/core/keyring")
        if blob is None:
            raise VaultError("not initialized")
        try:
            self._barrier = open_bytes(b64d(unseal_key_b64), blob[0])
        except (VaultError, ValueError):  # wrong key, or not even valid base64
            return False
        self.sealed = False
        return True

    # ----- tokens
    def _new_token(self, policies: list[str], ttl: int | None, max_ttl: int | None = 86_400) -> str:
        tok = "mvt." + secrets.token_urlsafe(18)
        now = self.clock.now()
        self.tokens[tok] = {
            "policies": policies, "created": now, "max_expire": None if ttl is None else now + (max_ttl or ttl),
            "expire": None if ttl is None else now + ttl, "accessor": secrets.token_hex(6),
        }
        return tok

    def _lookup(self, token: str | None) -> dict | None:
        entry = self.tokens.get(token or "")
        if entry is None:
            return None
        if entry["expire"] is not None and entry["expire"] <= self.clock.now():
            self.tokens.pop(token, None)
            return None
        return entry

    def _allowed(self, entry: dict, path: str, op: str) -> bool:
        if "root" in entry["policies"]:
            return True
        granted: set[str] = set()
        for name in entry["policies"]:
            doc = self._get(f"policy/{name}")
            for pattern, caps in (doc or {}).items():
                if path_matches(pattern, path):
                    granted |= set(caps)
        if "deny" in granted:
            return False
        return op in granted or (op == "update" and "create" in granted)

    # ----- dynamic secrets
    def _expire_leases(self) -> None:
        now = self.clock.now()
        for lid in [k for k, v in self.leases.items() if v["expire"] <= now]:
            self._revoke(lid)

    def _revoke(self, lease_id: str) -> bool:
        lease = self.leases.pop(lease_id, None)
        if lease and self.database:
            self.database.drop_user(lease["username"])
        return lease is not None

    # ----- request entry point
    def request(self, method: str, path: str, token: str | None = None, body: dict | None = None, query: dict | None = None) -> tuple[int, dict]:
        path = path.strip("/")
        if path.startswith("v1/"):
            path = path[3:]
        body, query = body or {}, query or {}
        method = method.upper()
        if method == "GET" and query.get("list") in ("true", True):
            method = "LIST"
        if not self.sealed:
            self._expire_leases()
        status, payload = self._dispatch(method, path, token, body, query)
        entry = self.tokens.get(token or "")
        self.audit_log.append({
            "time": self.clock.now(), "method": method, "path": path, "status": status,
            "accessor_hmac": hmac.new(self._audit_salt, (token or "").encode(), hashlib.sha256).hexdigest()[:12],
            "request_keys": sorted(body.keys()), "policies": entry["policies"] if entry else None,
        })
        return status, payload

    def _dispatch(self, method: str, path: str, token: str | None, body: dict, query: dict) -> tuple[int, dict]:
        if path == "sys/seal-status":
            return 200, {"sealed": self.sealed, "initialized": self.initialized, "storage_type": self.backend.kind}
        if path == "sys/unseal" and method in ("POST", "PUT"):
            ok = self.initialized and self.unseal(body.get("key", ""))
            return (200, {"sealed": False}) if ok else (400, {"errors": ["invalid unseal key"]})
        if self.sealed:
            return 503, {"errors": ["Vault is sealed"]}
        if path == "auth/approle/login" and method in ("POST", "PUT"):
            return self._approle_login(body)
        entry = self._lookup(token)
        if entry is None:
            return 403, {"errors": ["permission denied"]}
        op = {"GET": "read", "LIST": "list", "DELETE": "delete", "POST": "update", "PUT": "update"}.get(method)
        if op is None:
            return 405, {"errors": ["method not allowed"]}
        if path not in ANY_TOKEN_PATHS and not self._allowed(entry, path, op):
            return 403, {"errors": ["permission denied"]}
        try:
            return self._route(method, path, token, entry, body, query)
        except VaultError as exc:
            return 400, {"errors": [str(exc)]}

    # ----- routing
    def _route(self, method: str, path: str, token: str, entry: dict, body: dict, query: dict) -> tuple[int, dict]:
        p = path.split("/")
        if path == "sys/seal" and method in ("POST", "PUT"):
            self.seal()
            return 204, {}
        if p[:3] == ["sys", "policies", "acl"] and len(p) == 4 and method in ("POST", "PUT"):
            doc = body.get("policy", {})
            for pattern, caps in doc.items():
                if not set(caps) <= CAPS:
                    raise VaultError(f"unknown capability in {pattern}")
            self._put(f"policy/{p[3]}", doc)
            return 204, {}
        if p[:3] == ["auth", "token", "create"]:
            return self._token_create(entry, body)
        if path == "auth/token/lookup-self":
            ttl = None if entry["expire"] is None else int(entry["expire"] - self.clock.now())
            return 200, {"data": {"policies": entry["policies"], "ttl": ttl, "accessor": entry["accessor"]}}
        if path == "auth/token/renew-self":
            return self._token_renew(entry, body)
        if path == "auth/token/revoke-self":
            self.tokens.pop(token, None)
            return 204, {}
        if p[:3] == ["auth", "approle", "role"]:
            return self._approle_admin(p, method, body)
        if p[0] == "secret":
            return self._kv(p, method, body, query)
        if p[0] == "transit":
            return self._transit(p, method, body)
        if p[:2] == ["database", "roles"] and len(p) == 3 and method in ("POST", "PUT"):
            self._put(f"dbrole/{p[2]}", {"default_ttl": int(body.get("default_ttl", 300)), "max_ttl": int(body.get("max_ttl", 3600))})
            return 204, {}
        if p[:2] == ["database", "creds"] and len(p) == 3 and method == "GET":
            return self._db_creds(p[2])
        if p[:3] == ["sys", "leases", "renew"] and method in ("POST", "PUT"):
            return self._lease_renew(body)
        if p[:3] == ["sys", "leases", "revoke"] and method in ("POST", "PUT"):
            return (204, {}) if self._revoke(body.get("lease_id", "")) else (400, {"errors": ["lease not found"]})
        return 404, {"errors": ["unsupported path"]}

    # ----- tokens and approle
    def _token_create(self, parent: dict, body: dict) -> tuple[int, dict]:
        policies = list(body.get("policies", []))
        if "root" not in parent["policies"] and not set(policies) <= set(parent["policies"]):
            raise VaultError("child token cannot have policies its parent lacks")
        tok = self._new_token(policies, ttl=int(body.get("ttl", 3600)), max_ttl=int(body.get("max_ttl", 86_400)))
        return 200, {"auth": {"client_token": tok, "policies": policies, "lease_duration": int(body.get("ttl", 3600)), "renewable": True}}

    def _token_renew(self, entry: dict, body: dict) -> tuple[int, dict]:
        if entry["expire"] is None:
            raise VaultError("root tokens do not expire")
        inc = int(body.get("increment", 3600))
        new_expire = min(self.clock.now() + inc, entry["max_expire"])
        entry["expire"] = new_expire
        return 200, {"auth": {"lease_duration": int(new_expire - self.clock.now())}}

    def _approle_admin(self, p: list[str], method: str, body: dict) -> tuple[int, dict]:
        name = p[3]
        if len(p) == 4 and method in ("POST", "PUT"):
            self._put(f"approle/{name}", {"policies": body.get("policies", []), "role_id": "role-" + secrets.token_hex(8),
                                          "token_ttl": int(body.get("token_ttl", 600))})
            return 204, {}
        doc = self._get(f"approle/{name}")
        if doc is None:
            return 404, {"errors": ["role not found"]}
        if p[4:] == ["role-id"] and method == "GET":
            return 200, {"data": {"role_id": doc["role_id"]}}
        if p[4:] == ["secret-id"] and method in ("POST", "PUT"):
            sid = secrets.token_urlsafe(16)
            self._secret_ids[sid] = {"role": name, "uses_left": int(body.get("num_uses", 1))}
            return 200, {"data": {"secret_id": sid}}
        return 404, {"errors": ["unsupported path"]}

    def _approle_login(self, body: dict) -> tuple[int, dict]:
        sid = self._secret_ids.get(body.get("secret_id", ""))
        if not sid:
            return 400, {"errors": ["invalid role or secret ID"]}
        role = self._get(f"approle/{sid['role']}")
        if not role or role["role_id"] != body.get("role_id"):
            return 400, {"errors": ["invalid role or secret ID"]}
        sid["uses_left"] -= 1
        if sid["uses_left"] <= 0:
            self._secret_ids.pop(body["secret_id"], None)  # one-time secret id
        tok = self._new_token(role["policies"], ttl=role["token_ttl"])
        return 200, {"auth": {"client_token": tok, "policies": role["policies"], "lease_duration": role["token_ttl"]}}

    # ----- KV v2
    def _kv(self, p: list[str], method: str, body: dict, query: dict) -> tuple[int, dict]:
        kind, sub = p[1], "/".join(p[2:])
        now = int(self.clock.now())
        doc = self._get(f"kv/{sub}") if kind != "metadata" or method != "LIST" else None
        if kind == "data" and method in ("POST", "PUT"):
            doc = doc or {"current": 0, "versions": {}, "max_versions": 5}
            cas = (body.get("options") or {}).get("cas")
            if cas is not None and cas != doc["current"]:
                raise VaultError(f"check-and-set parameter did not match the current version ({doc['current']})")
            doc["current"] += 1
            doc["versions"][str(doc["current"])] = {"data": body.get("data", {}), "created": now, "deleted": None, "destroyed": False}
            for old in sorted(map(int, doc["versions"]))[:-doc["max_versions"]]:
                doc["versions"].pop(str(old))
            self._put(f"kv/{sub}", doc)
            return 200, {"data": {"version": doc["current"], "created_time": now}}
        if kind == "data" and method == "GET":
            if doc is None:
                return 404, {"errors": []}
            v = str(query.get("version", doc["current"]))
            ver = doc["versions"].get(v)
            if ver is None or ver["deleted"] or ver["destroyed"]:
                return 404, {"errors": []}
            return 200, {"data": {"data": ver["data"], "metadata": {"version": int(v), "created_time": ver["created"]}}}
        if kind == "data" and method == "DELETE" and doc:
            doc["versions"][str(doc["current"])]["deleted"] = now
            self._put(f"kv/{sub}", doc)
            return 204, {}
        if kind in ("undelete", "destroy") and method in ("POST", "PUT") and doc:
            for v in map(str, body.get("versions", [])):
                if v in doc["versions"]:
                    if kind == "undelete":
                        doc["versions"][v]["deleted"] = None
                    else:
                        doc["versions"][v].update(destroyed=True, data={})
            self._put(f"kv/{sub}", doc)
            return 204, {}
        if kind == "metadata" and method == "GET" and doc:
            return 200, {"data": {"current_version": doc["current"], "max_versions": doc["max_versions"],
                                  "versions": {v: {"created_time": x["created"], "deletion_time": x["deleted"], "destroyed": x["destroyed"]}
                                               for v, x in doc["versions"].items()}}}
        if kind == "metadata" and method == "LIST":
            prefix = "vault/kv/" + (sub + "/" if sub else "")
            children = sorted({k[len(prefix):].split("/")[0] + ("/" if "/" in k[len(prefix):] else "") for k in self.backend.list(prefix)})
            return (200, {"data": {"keys": children}}) if children else (404, {"errors": []})
        return 404, {"errors": ["not found"]}

    # ----- transit
    def _transit(self, p: list[str], method: str, body: dict) -> tuple[int, dict]:
        action = p[1]
        name = p[2] if len(p) > 2 else ""
        now = int(self.clock.now())
        if action == "keys" and len(p) == 3 and method in ("POST", "PUT"):
            if self._get(f"transit/{name}") is None:
                self._put(f"transit/{name}", {"latest": 1, "versions": {"1": {"key": b64e(secrets.token_bytes(32)), "created": now}}})
            return 204, {}
        doc = self._get(f"transit/{name}")
        if doc is None:
            return 404, {"errors": ["encryption key not found"]}
        if action == "keys" and len(p) == 3 and method == "GET":
            # metadata only: the key material is never returned (the key is not exportable)
            return 200, {"data": {"name": name, "type": "teaching-hmac-stream", "latest_version": doc["latest"],
                                  "exportable": False, "keys": {v: x["created"] for v, x in doc["versions"].items()}}}
        if action == "keys" and p[3:] == ["rotate"] and method in ("POST", "PUT"):
            doc["latest"] += 1
            doc["versions"][str(doc["latest"])] = {"key": b64e(secrets.token_bytes(32)), "created": now}
            self._put(f"transit/{name}", doc)
            return 204, {}
        aad = body.get("context", "").encode()
        if action == "encrypt" and method in ("POST", "PUT"):
            ver = str(doc["latest"])
            blob = seal_bytes(b64d(doc["versions"][ver]["key"]), b64d(body["plaintext"]), aad)
            return 200, {"data": {"ciphertext": f"vault:v{ver}:{b64e(blob)}"}}
        if action in ("decrypt", "rewrap") and method in ("POST", "PUT"):
            try:
                _tag, ver, blob = body["ciphertext"].split(":", 2)
                plain = open_bytes(b64d(doc["versions"][ver[1:]]["key"]), b64d(blob), aad)
            except (KeyError, ValueError) as exc:
                raise VaultError("invalid ciphertext") from exc
            if action == "decrypt":
                return 200, {"data": {"plaintext": b64e(plain)}}
            latest = str(doc["latest"])
            return 200, {"data": {"ciphertext": f"vault:v{latest}:{b64e(seal_bytes(b64d(doc['versions'][latest]['key']), plain, aad))}"}}
        return 404, {"errors": ["unsupported path"]}

    # ----- dynamic database credentials and leases
    def _db_creds(self, role: str) -> tuple[int, dict]:
        cfg = self._get(f"dbrole/{role}")
        if cfg is None or self.database is None:
            return 404, {"errors": ["role not found"]}
        user, password = f"v-{role}-{secrets.token_hex(4)}", secrets.token_urlsafe(16)
        self.database.create_user(user, password)
        lid = f"database/creds/{role}/{secrets.token_hex(6)}"
        now = self.clock.now()
        self.leases[lid] = {"username": user, "expire": now + cfg["default_ttl"], "max_expire": now + cfg["max_ttl"]}
        return 200, {"lease_id": lid, "lease_duration": cfg["default_ttl"], "renewable": True, "data": {"username": user, "password": password}}

    def _lease_renew(self, body: dict) -> tuple[int, dict]:
        lease = self.leases.get(body.get("lease_id", ""))
        if lease is None:
            raise VaultError("lease not found or expired")
        now = self.clock.now()
        lease["expire"] = min(now + int(body.get("increment", 300)), lease["max_expire"])
        return 200, {"lease_id": body["lease_id"], "lease_duration": int(lease["expire"] - now)}


# ---------------------------------------------------------------- transports and the client the "app" uses
Transport = Callable[[str, str, "str | None", "dict | None", "dict | None"], "tuple[int, dict]"]


class InProcessTransport:
    def __init__(self, vault: MiniVault) -> None:
        self.vault = vault

    def __call__(self, method: str, path: str, token: str | None = None, body: dict | None = None, query: dict | None = None):
        return self.vault.request(method, path, token, body, query)


class RecordingTransport:
    """Wraps a transport and keeps every response the application ever received."""

    def __init__(self, inner: Transport) -> None:
        self.inner = inner
        self.responses: list[str] = []

    def __call__(self, method: str, path: str, token: str | None = None, body: dict | None = None, query: dict | None = None):
        status, payload = self.inner(method, path, token, body, query)
        self.responses.append(json.dumps(payload))
        return status, payload

    @property
    def transcript(self) -> str:
        return "\n".join(self.responses)


class HttpTransport:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")

    def __call__(self, method: str, path: str, token: str | None = None, body: dict | None = None, query: dict | None = None):
        url = f"{self.base}/v1/{path.strip('/')}"
        if query:
            url += "?" + "&".join(f"{k}={v}" for k, v in query.items())
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method="PUT" if method == "LIST" else method)
        if method == "LIST":
            req = urllib.request.Request(url + ("&" if "?" in url else "?") + "list=true", method="GET")
        if token:
            req.add_header("X-Vault-Token", token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            return exc.code, (json.loads(raw) if raw else {})


class VaultClient:
    """What application code uses. It holds a token, never a key."""

    def __init__(self, transport: Transport, token: str | None = None) -> None:
        self.t, self.token = transport, token

    def call(self, method: str, path: str, body: dict | None = None, query: dict | None = None) -> dict:
        status, payload = self.t(method, path, self.token, body, query)
        if status >= 400:
            raise VaultError(f"{status} {payload.get('errors')}")
        return payload

    def approle_login(self, role_id: str, secret_id: str) -> str:
        self.token = self.call("POST", "auth/approle/login", {"role_id": role_id, "secret_id": secret_id})["auth"]["client_token"]
        return self.token

    def kv_put(self, path: str, data: dict, cas: int | None = None) -> int:
        body: dict[str, Any] = {"data": data}
        if cas is not None:
            body["options"] = {"cas": cas}
        return self.call("POST", f"secret/data/{path}", body)["data"]["version"]

    def kv_get(self, path: str, version: int | None = None) -> dict:
        return self.call("GET", f"secret/data/{path}", query={"version": version} if version else None)["data"]["data"]

    def encrypt(self, key: str, plaintext: bytes, context: str = "") -> str:
        return self.call("POST", f"transit/encrypt/{key}", {"plaintext": b64e(plaintext), "context": context})["data"]["ciphertext"]

    def decrypt(self, key: str, ciphertext: str, context: str = "") -> bytes:
        return b64d(self.call("POST", f"transit/decrypt/{key}", {"ciphertext": ciphertext, "context": context})["data"]["plaintext"])

    def db_creds(self, role: str) -> dict:
        return self.call("GET", f"database/creds/{role}")


# ---------------------------------------------------------------- optional HTTP server on 127.0.0.1
def serve(vault: MiniVault) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def _handle(self, method: str) -> None:
            path, _, qs = self.path.partition("?")
            query = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else {}
            with lock:
                status, payload = vault.request(method, path, self.headers.get("X-Vault-Token"), body, query)
            raw = json.dumps(payload).encode() if status != 204 else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None: self._handle("GET")  # noqa: E704
        def do_POST(self) -> None: self._handle("POST")  # noqa: E704
        def do_PUT(self) -> None: self._handle("PUT")  # noqa: E704
        def do_DELETE(self) -> None: self._handle("DELETE")  # noqa: E704

        def log_message(self, *args: Any) -> None:  # silence
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # loopback only, random free port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, f"http://127.0.0.1:{httpd.server_address[1]}"


def bootstrap(backend: _MemoryBackend | None = None, clock: Clock | None = None) -> tuple[MiniVault, str, str]:
    """Create, initialise and return (vault, root_token, unseal_key_b64)."""
    vault = MiniVault(backend, clock)
    keys = vault.initialize()
    vault.database = FakeDatabase()
    return vault, keys["root_token"], keys["unseal_key"]
