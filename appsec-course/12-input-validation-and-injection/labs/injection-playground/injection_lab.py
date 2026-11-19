"""SQL, ORM, NoSQL injection and SSRF: vulnerable vs secure, all in-process.

- SQL: sqlite3 in memory. Vulnerable = string formatting; secure = bind variables.
- ORM: a mini ORM whose order_by() pastes text into SQL (like Django .extra/RawSQL
  or Sequelize literal misuse). Secure = allowlist of column names.
- NoSQL: a mini Mongo-style matcher that understands $ne/$gt/$regex operators.
  Vulnerable login passes JSON from the client straight into the query.
- SSRF: a FAKE network (a dict). No real requests are made. The cloud metadata URL
  holds a FAKE canary credential so you can see the impact.
Secrets are built at runtime and labelled FAKE.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import sqlite3
from urllib.parse import urlparse

ADMIN_PW = "FAKE-" + secrets.token_hex(4)

# ------------------------------------------------------------------ SQL


def make_db() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.executescript("""
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL, hidden INTEGER);
        CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, password TEXT);
        INSERT INTO products(name, price, hidden) VALUES ('pen', 10, 0), ('book', 250, 0),
            ('lamp', 900, 0), ('unreleased-phone', 99999, 1);
    """)
    c.execute("INSERT INTO users(name, password) VALUES ('admin', ?)", (ADMIN_PW,))
    return c


def search_vuln(c, term: str):
    sql = f"SELECT name, price FROM products WHERE hidden = 0 AND name LIKE '%{term}%'"
    return c.execute(sql).fetchall()


def search_safe(c, term: str):
    # bind variable: the term is data, never SQL (like :term in Oracle)
    return c.execute("SELECT name, price FROM products WHERE hidden = 0 AND name LIKE ?", (f"%{term}%",)).fetchall()


# ------------------------------------------------------------------ ORM


class MiniORM:
    COLUMNS = {"id", "name", "price"}

    def __init__(self, conn, secure: bool):
        self.c, self.secure = conn, secure

    def products(self, name_filter: str = "", order_by: str = "name"):
        if self.secure:
            direction = "DESC" if order_by.startswith("-") else "ASC"
            col = order_by.lstrip("-")
            if col not in self.COLUMNS:
                raise ValueError(f"invalid sort field {order_by!r}")
            order_sql = f"{col} {direction}"  # identifier from an allowlist, never user text
        else:
            order_sql = order_by  # "raw" escape hatch: user text becomes SQL
        sql = f"SELECT name FROM products WHERE hidden = 0 AND name LIKE ? ORDER BY {order_sql}"
        return [r[0] for r in self.c.execute(sql, (f"%{name_filter}%",)).fetchall()]


def orm_order_by_oracle(orm: MiniORM, guess_char: str, pos: int) -> bool:
    """Boolean oracle through ORDER BY: the sort order reveals whether a guess is right."""
    expr = (f"(CASE WHEN substr((SELECT password FROM users WHERE name='admin'),{pos},1)='{guess_char}' "
            f"THEN price ELSE -price END)")
    return orm.products(order_by=expr)[0] == "pen"


def orm_extract_password(orm: MiniORM, length: int) -> str:
    alphabet = "FAKE-0123456789abcdef"
    out = ""
    for pos in range(1, length + 1):
        out += next((ch for ch in alphabet if orm_order_by_oracle(orm, ch, pos)), "?")
    return out


# ------------------------------------------------------------------ NoSQL


def _match(doc: dict, query: dict) -> bool:
    for key, cond in query.items():
        val = doc.get(key)
        if isinstance(cond, dict):  # operator object
            for op, arg in cond.items():
                if op == "$ne" and not val != arg:
                    return False
                if op == "$gt" and not (val is not None and val > arg):
                    return False
                if op == "$regex" and not re.search(arg, str(val)):
                    return False
        elif val != cond:
            return False
    return True


USERS_COLL = [{"username": "admin", "password": ADMIN_PW, "role": "admin"},
              {"username": "alice", "password": "FAKE-alice-pw", "role": "user"}]


def nosql_login_vuln(body: dict):
    q = {"username": body.get("username"), "password": body.get("password")}
    return next((u for u in USERS_COLL if _match(u, q)), None)


def nosql_login_safe(body: dict):
    user, pw = body.get("username"), body.get("password")
    if not isinstance(user, str) or not isinstance(pw, str):  # reject operator objects
        raise ValueError("username and password must be strings")
    q = {"username": user, "password": pw}
    return next((u for u in USERS_COLL if _match(u, q)), None)


# ------------------------------------------------------------------ SSRF

METADATA_CANARY = "FAKE-IAM-CREDENTIAL-" + secrets.token_hex(4)
FAKE_DNS = {"images.partner.example": "93.184.216.34", "metadata.attacker.example": "169.254.169.254",
            "internal-admin.corp": "10.0.0.5"}
FAKE_WEB = {
    "93.184.216.34": "<img data>",
    "169.254.169.254": "iam/security-credentials/app-role: " + METADATA_CANARY,
    "10.0.0.5": "internal admin panel",
    "127.0.0.1": "local debug console",
}


def _resolve(host: str) -> str:
    if host in FAKE_DNS:
        return FAKE_DNS[host]
    if host.isdigit():  # decimal IP trick: http://2852039166/
        return str(ipaddress.ip_address(int(host)))
    return host


def fake_fetch(url: str) -> str:
    ip = _resolve(urlparse(url).hostname or "")
    return FAKE_WEB.get(ip, "404")


def preview_vuln(url: str) -> str:
    return fake_fetch(url)


ALLOWED_HOSTS = {"images.partner.example"}


def preview_safe(url: str) -> str:
    p = urlparse(url)
    if p.scheme != "https":
        raise ValueError("only https")
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not in allowlist")
    ip = ipaddress.ip_address(_resolve(p.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("resolves to an internal address")  # stops DNS tricks too
    return fake_fetch(url)  # real code: connect to the checked IP, no redirects
