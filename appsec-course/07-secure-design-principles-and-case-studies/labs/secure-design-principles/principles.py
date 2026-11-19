"""Saltzer and Schroeder's design principles (1975) as vulnerable vs principled code pairs.

Each pair solves the same small problem. The tests run the same attack against both versions:
it works against the vulnerable one and fails against the principled one.
All data, users and keys are fictional; the HMAC key is generated at runtime.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3


# 1. Economy of mechanism -------------------------------------------------------------------
class ManyPathAuth:
    """Three ways in, grown over the years. The legacy header path was 'only for internal tools'."""

    def __init__(self, sessions: dict[str, str], api_keys: dict[str, str]):
        self.sessions, self.api_keys = sessions, api_keys

    def authenticate(self, headers: dict[str, str]) -> str | None:
        if "Cookie" in headers:
            return self.sessions.get(headers["Cookie"].removeprefix("sid="))
        if "X-Api-Key" in headers:
            return self.api_keys.get(headers["X-Api-Key"])
        if "X-Internal-User" in headers:  # legacy: trusted because "only the intranet sends it"
            return headers["X-Internal-User"]
        return None


class OnePathAuth:
    """One small mechanism: an opaque bearer token looked up server side. Easy to review and test."""

    def __init__(self, tokens: dict[str, str]):
        self.tokens = tokens

    def authenticate(self, headers: dict[str, str]) -> str | None:
        auth = headers.get("Authorization", "")
        return self.tokens.get(auth.removeprefix("Bearer ")) if auth.startswith("Bearer ") else None


# 2. Fail-safe defaults ----------------------------------------------------------------------
def allowed_fail_open(user: dict, action: str, acl: dict[str, set[str]]) -> bool:
    try:
        return action in acl[user["role"]]
    except Exception:  # unknown role, missing field ... "don't block the business"
        return True


def allowed_fail_safe(user: dict, action: str, acl: dict[str, set[str]]) -> bool:
    role = user.get("role")
    return isinstance(role, str) and action in acl.get(role, set())


# 3. Complete mediation ----------------------------------------------------------------------
class CachedAuthz:
    """Checks permissions once at login and trusts the session afterwards."""

    def __init__(self, store: dict[str, set[str]]):
        self.store, self.sessions = store, {}

    def login(self, user: str) -> str:
        sid = secrets.token_hex(8)
        self.sessions[sid] = set(self.store.get(user, set()))  # snapshot
        return sid

    def can(self, sid: str, action: str) -> bool:
        return action in self.sessions.get(sid, set())


class MediatedAuthz:
    """Checks the current permission store on EVERY access, so revocation takes effect at once."""

    def __init__(self, store: dict[str, set[str]]):
        self.store, self.sessions = store, {}

    def login(self, user: str) -> str:
        sid = secrets.token_hex(8)
        self.sessions[sid] = user
        return sid

    def can(self, sid: str, action: str) -> bool:
        user = self.sessions.get(sid)
        return user is not None and action in self.store.get(user, set())


# 4. Open design -----------------------------------------------------------------------------
def obscure_token(user_id: int) -> str:
    """'Nobody knows our format' (base64 of 'uid:<id>'). Security depends on the design staying secret."""
    return base64.urlsafe_b64encode(f"uid:{user_id}".encode()).decode()


def obscure_verify(token: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
    except Exception:
        return None
    return int(raw[4:]) if raw.startswith("uid:") else None


def open_token(user_id: int, key: bytes) -> str:
    """Public design (HMAC-SHA256), secret key. Knowing the design does not help the attacker."""
    mac = hmac.new(key, f"uid:{user_id}".encode(), hashlib.sha256).hexdigest()
    return f"{user_id}.{mac}"


def open_verify(token: str, key: bytes) -> int | None:
    uid, _, mac = token.partition(".")
    if not uid.isdigit():
        return None
    expected = hmac.new(key, f"uid:{uid}".encode(), hashlib.sha256).hexdigest()
    return int(uid) if hmac.compare_digest(mac, expected) else None


# 5. Separation of privilege ------------------------------------------------------------------
def refund_single_key(amount: int, requester: str, approvers: list[str]) -> bool:
    return len(approvers) >= 1  # anyone, even the requester, approves anything


def refund_two_person(amount: int, requester: str, approvers: list[str], threshold: int = 10_000) -> bool:
    distinct = {a for a in approvers if a != requester}
    return len(distinct) >= (2 if amount > threshold else 1)


# 6. Least privilege --------------------------------------------------------------------------
def report_db(least_privilege: bool) -> sqlite3.Connection:
    """An ad-hoc reporting feature: users type SQL. The connection's privileges decide the blast radius."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer TEXT, total INTEGER)")
    conn.executemany("INSERT INTO orders (customer, total) VALUES (?, ?)", [("alice", 120), ("bob", 80)])
    conn.commit()
    if least_privilege:
        read_only = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}

        def authorizer(action, *_):
            return sqlite3.SQLITE_OK if action in read_only else sqlite3.SQLITE_DENY

        conn.set_authorizer(authorizer)  # like GRANT SELECT ON orders TO report_user, and nothing else
    return conn


def run_report(conn: sqlite3.Connection, sql: str):
    return conn.execute(sql).fetchall()


# 7. Least common mechanism -------------------------------------------------------------------
class SharedReportCache:
    """One cache shared by all tenants, keyed only by report name."""

    def __init__(self):
        self.cache: dict[str, str] = {}

    def get(self, tenant: str, report: str, build) -> str:
        if report not in self.cache:
            self.cache[report] = build(tenant, report)
        return self.cache[report]


class TenantReportCache:
    """Separate mechanism state per tenant: nothing is shared that does not need to be."""

    def __init__(self):
        self.cache: dict[tuple[str, str], str] = {}

    def get(self, tenant: str, report: str, build) -> str:
        key = (tenant, report)
        if key not in self.cache:
            self.cache[key] = build(tenant, report)
        return self.cache[key]


# 8. Psychological acceptability ----------------------------------------------------------------
def complexity_policy(pw: str) -> bool:
    """Classic rules users hate: they comply with predictable patterns such as Season+Year+!"""
    return (len(pw) >= 8 and re.search(r"[A-Z]", pw) is not None and re.search(r"[a-z]", pw) is not None
            and re.search(r"\d", pw) is not None and re.search(r"[^A-Za-z0-9]", pw) is not None)


BLOCKLIST = re.compile(r"(password|qwerty|letmein|welcome|(spring|summer|autumn|fall|winter)\W*\d{2,4})", re.I)


def usable_policy(pw: str) -> bool:
    """NIST SP 800-63B-4 style (verify): length over complexity, blocklist, no composition rules, no rotation."""
    return len(pw) >= 15 and not BLOCKLIST.search(pw)
