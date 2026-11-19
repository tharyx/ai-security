"""SQL injection authentication bypass on a real sqlite3 database, and the
parameterized fix.

Covers "Exploiting Broken Authentication With SQL Injection". The vulnerable
login builds a query by string concatenation, so ``' OR '1'='1' --`` logs in
without a password. The secure login uses bound parameters (the DBA's "bind
variables"), so the same input is treated as data, not SQL.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import hashlib
import sqlite3


def make_db() -> sqlite3.Connection:
    """An in-memory users table with two accounts (passwords are toy values)."""
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (username TEXT PRIMARY KEY, pw_hash TEXT, role TEXT)")
    for user, pw, role in [("alice", "pw-alice", "user"), ("admin", "pw-admin", "admin")]:
        con.execute("INSERT INTO users VALUES (?, ?, ?)",
                    (user, _hash(pw), role))
    con.commit()
    return con


def _hash(pw: str) -> str:
    # A toy hash so the stored value is not the plaintext. Real storage would
    # use a slow salted KDF (see the password-hash-cracking lab).
    return hashlib.sha256(pw.encode()).hexdigest()


def login_vulnerable(con: sqlite3.Connection, username: str, password: str):
    """Builds the WHERE clause by concatenation. INJECTABLE on purpose."""
    pw_hash = _hash(password)
    query = (
        "SELECT username, role FROM users "
        f"WHERE username = '{username}' AND pw_hash = '{pw_hash}'"
    )
    # executescript is not used; a single statement still allows boolean bypass.
    row = con.execute(query).fetchone()
    return {"username": row[0], "role": row[1]} if row else None


def login_secure(con: sqlite3.Connection, username: str, password: str):
    """Uses bound parameters; the input can never change the query structure."""
    row = con.execute(
        "SELECT username, role FROM users WHERE username = ? AND pw_hash = ?",
        (username, _hash(password)),
    ).fetchone()
    return {"username": row[0], "role": row[1]} if row else None


# A classic bypass payload for the username field. No password needed.
BYPASS_USERNAME = "' OR '1'='1' -- "
BYPASS_ADMIN = "admin' -- "
