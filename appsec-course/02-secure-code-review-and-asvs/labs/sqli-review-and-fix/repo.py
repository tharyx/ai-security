"""Data-access code to review for SQL injection, with fixed versions next to each bug.

Four patterns a reviewer meets in real code:
1. value concatenated into WHERE          -> bind parameter (?)            [like Oracle :bind variables]
2. login query built from strings         -> bind parameter + compare hash in code
3. ORDER BY column taken from the request  -> identifiers cannot be bound: map to an allowlist
4. IN (...) list built from a CSV string   -> generate one ? per item, bind each value

sqlite3 in memory only. Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3


def toy_hash(pw: str) -> str:  # toy only; real apps use Argon2id/scrypt/bcrypt/PBKDF2 with a salt
    return hashlib.sha256(("lab-salt" + pw).encode()).hexdigest()


def make_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, hidden INTEGER);
        """
    )
    db.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "alice", toy_hash("alice-lab-pw"), "customer"),
        (2, "admin", toy_hash("admin-lab-pw"), "admin"),
    ])
    db.executemany("INSERT INTO products VALUES (?,?,?,?)", [
        (1, "Apple juice", 3.0, 0), (2, "Banana bread", 5.0, 0), (3, "Cherry jam", 4.0, 0),
        (4, "Staff-only sample", 0.0, 1),
    ])
    return db


# ------------------------------------------------------------------ 1. search

def search_vuln(db, name: str) -> list:
    sql = "SELECT name, price FROM products WHERE hidden = 0 AND name LIKE '%" + name + "%'"
    return db.execute(sql).fetchall()


def search_fixed(db, name: str) -> list:
    return db.execute("SELECT name, price FROM products WHERE hidden = 0 AND name LIKE ?",
                      (f"%{name}%",)).fetchall()


# ------------------------------------------------------------------ 2. login

def login_vuln(db, username: str, password: str):
    sql = (f"SELECT id, role FROM users WHERE username = '{username}' "
           f"AND password_hash = '{toy_hash(password)}'")
    return db.execute(sql).fetchone()


def login_fixed(db, username: str, password: str):
    row = db.execute("SELECT id, role, password_hash FROM users WHERE username = :u",
                     {"u": username}).fetchone()
    if row and hmac.compare_digest(row[2], toy_hash(password)):
        return row[0], row[1]
    return None


# ------------------------------------------------------------------ 3. ORDER BY

def list_sorted_vuln(db, sort: str) -> list:
    return [r[0] for r in db.execute(f"SELECT name FROM products WHERE hidden = 0 ORDER BY {sort}")]


SORT_COLUMNS = {"name": "name", "price": "price", "-price": "price DESC"}


def list_sorted_fixed(db, sort: str) -> list:
    order = SORT_COLUMNS.get(sort)
    if order is None:
        raise ValueError("unsupported sort key")
    return [r[0] for r in db.execute(f"SELECT name FROM products WHERE hidden = 0 ORDER BY {order}")]


def order_by_oracle(list_fn, db, condition: str) -> list:
    """Blind boolean inference through ORDER BY: the row order reveals whether `condition` is true."""
    return list_fn(db, f"(CASE WHEN ({condition}) THEN name ELSE price END)")


# ------------------------------------------------------------------ 4. IN list

def by_ids_vuln(db, ids_csv: str) -> list:
    return [r[0] for r in db.execute(f"SELECT name FROM products WHERE hidden = 0 AND id IN ({ids_csv})")]


def by_ids_fixed(db, ids_csv: str) -> list:
    ids = [int(x) for x in ids_csv.split(",") if x.strip()]  # int() rejects '1) OR (1=1'
    if not ids or len(ids) > 100:
        raise ValueError("between 1 and 100 ids")
    marks = ",".join("?" * len(ids))
    return [r[0] for r in db.execute(f"SELECT name FROM products WHERE hidden = 0 AND id IN ({marks})", ids)]
