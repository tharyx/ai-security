"""A Vault-like secret store, and an API service that creates and consumes secrets safely.

VaultLite mimics the SHAPE of HashiCorp Vault / OpenBao (verify real paths and behaviour at the docs):
  * tokens with policies, TTL and max TTL; AppRole-style login (role_id + single-use secret_id)
  * path policies with capabilities (create/read/update/delete/list), deny by default
  * KV v2: secret/data/<path> with versions; secret/metadata/<path>
  * dynamic database credentials: database/creds/<role> creates a user with a lease; revoke on expiry
  * an audit log that stores HMACs of secret values and tokens, never the values

It is not Vault: no encryption barrier, no seal, no storage backend. For those ideas see
devsecops-course/13-secrets-management/labs/vault-consul-secrets (MiniVault).

The two services show the contrast:
  * HardcodedOrdersService: the DB password sits in a config dict (and leaks into an error log)
  * VaultOrdersService: logs in with AppRole, reads its own path, uses short-lived DB creds,
    renews the lease, re-reads after rotation, and never logs secret values.
All secret values are FAKE and generated at runtime.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field


class VaultError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(f"{status}: {msg}")
        self.status = status


def fake_secret(label: str) -> str:
    return f"FAKE-{label}-" + secrets.token_hex(8)


class Clock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@dataclass
class FakeDatabase:
    users: dict[str, str] = field(default_factory=dict)

    def create_user(self, name: str, pw: str) -> None:
        self.users[name] = pw

    def drop_user(self, name: str) -> None:
        self.users.pop(name, None)

    def connect(self, name: str, pw: str) -> bool:
        return self.users.get(name) == pw


@dataclass
class VaultLite:
    clock: Clock = field(default_factory=Clock)
    db: FakeDatabase = field(default_factory=FakeDatabase)
    policies: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    tokens: dict[str, dict] = field(default_factory=dict)
    kv: dict[str, list[dict]] = field(default_factory=dict)
    approles: dict[str, dict] = field(default_factory=dict)
    leases: dict[str, dict] = field(default_factory=dict)
    audit: list[dict] = field(default_factory=list)
    _audit_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    # ---------------------------------------------------------- admin setup (done with a root/admin token in reality)
    def write_policy(self, name: str, rules: dict[str, set[str]]) -> None:
        self.policies[name] = rules

    def create_approle(self, role: str, policies: list[str], token_ttl: float, token_max_ttl: float) -> str:
        role_id = "role-" + secrets.token_hex(6)
        self.approles[role_id] = {"name": role, "policies": policies, "ttl": token_ttl, "max_ttl": token_max_ttl,
                                  "secret_ids": set()}
        return role_id

    def generate_secret_id(self, role_id: str) -> str:
        sid = fake_secret("secretid")
        self.approles[role_id]["secret_ids"].add(sid)
        return sid

    # ---------------------------------------------------------- helpers
    def _hmac(self, value: str) -> str:
        return "hmac-sha256:" + hmac.new(self._audit_key, value.encode(), hashlib.sha256).hexdigest()[:16]

    def _log(self, token: str | None, op: str, path: str, status: int, response_values: list[str] = ()) -> None:
        self.audit.append({"time": self.clock.now(), "token": self._hmac(token or "-"), "op": op, "path": path,
                           "status": status, "response": [self._hmac(v) for v in response_values]})

    def _expire(self) -> None:
        now = self.clock.now()
        for t in [t for t, e in self.tokens.items() if e["expires"] <= now]:
            del self.tokens[t]
        for lid in [l for l, e in self.leases.items() if e["expires"] <= now]:
            self.revoke_lease(lid)

    def _check(self, token: str | None, op: str, path: str) -> dict:
        self._expire()
        entry = self.tokens.get(token or "")
        if not entry:
            self._log(token, op, path, 403)
            raise VaultError(403, "permission denied (missing, invalid or expired token)")
        for pol in entry["policies"]:
            for pattern, caps in self.policies.get(pol, {}).items():
                if fnmatch.fnmatchcase(path, pattern) and "deny" not in caps and op in caps:
                    return entry
        self._log(token, op, path, 403)
        raise VaultError(403, f"permission denied: {op} on {path}")

    # ---------------------------------------------------------- auth
    def approle_login(self, role_id: str, secret_id: str) -> dict:
        role = self.approles.get(role_id)
        if not role or secret_id not in role["secret_ids"]:
            self._log(None, "login", "auth/approle/login", 400)
            raise VaultError(400, "invalid role_id or secret_id")
        role["secret_ids"].discard(secret_id)  # single use
        tok = "tok-" + secrets.token_hex(12)
        now = self.clock.now()
        self.tokens[tok] = {"policies": role["policies"], "expires": now + role["ttl"],
                            "max_expires": now + role["max_ttl"], "ttl": role["ttl"]}
        self._log(tok, "login", "auth/approle/login", 200)
        return {"client_token": tok, "lease_duration": role["ttl"]}

    def renew_self(self, token: str) -> float:
        self._expire()
        e = self.tokens.get(token)
        if not e:
            raise VaultError(403, "token expired")
        e["expires"] = min(self.clock.now() + e["ttl"], e["max_expires"])
        return e["expires"] - self.clock.now()

    # ---------------------------------------------------------- KV v2
    def kv_put(self, token: str, path: str, data: dict[str, str]) -> int:
        self._check(token, "create" if path not in self.kv else "update", f"secret/data/{path}")
        self.kv.setdefault(path, []).append({"data": dict(data), "created": self.clock.now()})
        version = len(self.kv[path])
        self._log(token, "write", f"secret/data/{path}", 200)
        return version

    def kv_get(self, token: str, path: str, version: int | None = None) -> dict:
        self._check(token, "read", f"secret/data/{path}")
        versions = self.kv.get(path)
        if not versions:
            raise VaultError(404, "not found")
        v = version or len(versions)
        data = versions[v - 1]["data"]
        self._log(token, "read", f"secret/data/{path}", 200, list(data.values()))
        return {"data": dict(data), "metadata": {"version": v}}

    # ---------------------------------------------------------- dynamic database secrets
    def db_creds(self, token: str, role: str, ttl: float = 3600) -> dict:
        self._check(token, "read", f"database/creds/{role}")
        user = f"v-{role}-{secrets.token_hex(4)}"
        pw = fake_secret("dbpw")
        self.db.create_user(user, pw)
        lid = f"database/creds/{role}/{secrets.token_hex(6)}"
        self.leases[lid] = {"user": user, "expires": self.clock.now() + ttl, "max": self.clock.now() + 4 * ttl, "ttl": ttl}
        self._log(token, "read", f"database/creds/{role}", 200, [pw])
        return {"lease_id": lid, "lease_duration": ttl, "data": {"username": user, "password": pw}}

    def renew_lease(self, token: str, lease_id: str) -> float:
        self._check(token, "update", "sys/leases/renew")
        self._expire()
        l = self.leases.get(lease_id)
        if not l:
            raise VaultError(400, "lease not found or expired")
        l["expires"] = min(self.clock.now() + l["ttl"], l["max"])
        return l["expires"] - self.clock.now()

    def revoke_lease(self, lease_id: str) -> None:
        l = self.leases.pop(lease_id, None)
        if l:
            self.db.drop_user(l["user"])


# ------------------------------------------------------------------ consumers
class HardcodedOrdersService:
    """VULNERABLE: one static DB password, in config, shared by every instance, printed on errors."""

    def __init__(self, db: FakeDatabase, config: dict):
        self.db, self.config = db, config
        self.log: list[str] = []

    def query(self) -> str:
        if not self.db.connect(self.config["db_user"], self.config["db_password"]):
            self.log.append(f"ERROR db connect failed with config={self.config}")  # leaks the secret
            return "error"
        return "rows"


class VaultOrdersService:
    """SECURE: AppRole login, least-privilege policy, dynamic DB creds with renewal, no secret logging."""

    def __init__(self, vault: VaultLite, role_id: str, secret_id: str):
        self.vault, self.log = vault, []
        self.token = vault.approle_login(role_id, secret_id)["client_token"]
        self.creds = vault.db_creds(self.token, "orders-rw", ttl=600)
        self.log.append(f"INFO got db lease {self.creds['lease_id']} user={self.creds['data']['username']}")

    def api_key_for_payments(self) -> str:
        return self.vault.kv_get(self.token, "orders/payments")["data"]["api_key"]

    def query(self) -> str:
        d = self.creds["data"]
        if not self.vault.db.connect(d["username"], d["password"]):
            self.log.append("ERROR db connect failed; requesting new credentials")
            self.creds = self.vault.db_creds(self.token, "orders-rw", ttl=600)
            d = self.creds["data"]
            return "rows" if self.vault.db.connect(d["username"], d["password"]) else "error"
        return "rows"

    def heartbeat(self) -> None:
        self.vault.renew_self(self.token)
        self.vault.renew_lease(self.token, self.creds["lease_id"])


def bootstrap() -> tuple[VaultLite, str, str, str]:
    """Admin setup: policies, an AppRole for the orders service, a payments API key, a static DB admin."""
    v = VaultLite()
    v.write_policy("admin", {"secret/data/*": {"create", "read", "update"}})
    v.write_policy("orders-svc", {
        "secret/data/orders/*": {"read"},
        "database/creds/orders-rw": {"read"},
        "sys/leases/renew": {"update"},
    })
    admin = "tok-admin-" + secrets.token_hex(6)
    v.tokens[admin] = {"policies": ["admin"], "expires": 10 ** 9, "max_expires": 10 ** 9, "ttl": 10 ** 9}
    v.kv_put(admin, "orders/payments", {"api_key": fake_secret("payments")})
    v.kv_put(admin, "billing/provider", {"api_key": fake_secret("billing")})
    role_id = v.create_approle("orders", ["orders-svc"], token_ttl=900, token_max_ttl=3600)
    return v, admin, role_id, v.generate_secret_id(role_id)
