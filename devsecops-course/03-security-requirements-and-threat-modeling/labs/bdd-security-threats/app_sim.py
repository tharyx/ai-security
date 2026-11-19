"""A tiny simulated web app used as the target of the BDD security scenarios.

No sockets: handle() is an ordinary function. `vulnerable=True` turns on realistic mistakes
(no lockout, user enumeration, SQL error leak, missing headers, weak cookie flags).
"""
from __future__ import annotations

from dataclasses import dataclass, field

USERS = {"alice": "correct-horse-battery", "bob": "tr0ub4dor-and-3"}
MAX_FAILURES = 5


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    cookies: list[str] = field(default_factory=list)   # raw Set-Cookie header values


class App:
    def __init__(self, vulnerable: bool = False):
        self.vulnerable = vulnerable
        self.failures: dict[str, int] = {}

    def _headers(self) -> dict:
        if self.vulnerable:
            return {"Server": "ShopServer/1.0.3"}
        return {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY"}

    def handle(self, method: str, path: str, params: dict | None = None, form: dict | None = None) -> Response:
        params, form = params or {}, form or {}
        if method == "GET" and path == "/":
            return Response(200, self._headers(), "<h1>Shop</h1>")
        if method == "POST" and path == "/login":
            return self._login(form.get("user", ""), form.get("password", ""))
        if method == "GET" and path == "/search":
            return self._search(params.get("q", ""))
        if method == "GET" and path == "/admin":
            return Response(404 if not self.vulnerable else 200, self._headers(), "admin panel" if self.vulnerable else "")
        return Response(404, self._headers(), "not found")

    def _login(self, user: str, password: str) -> Response:
        if not self.vulnerable and self.failures.get(user, 0) >= MAX_FAILURES:
            return Response(429, self._headers(), "too many attempts, try later")
        if user not in USERS:
            msg = "no such user" if self.vulnerable else "invalid credentials"
            return Response(401, self._headers(), msg)
        if USERS[user] != password:
            self.failures[user] = self.failures.get(user, 0) + 1
            return Response(401, self._headers(), "wrong password" if self.vulnerable else "invalid credentials")
        self.failures[user] = 0
        flags = "" if self.vulnerable else "; Secure; HttpOnly; SameSite=Lax"
        return Response(200, self._headers(), "welcome", [f"sid=SESSION-{user}{flags}"])

    def _search(self, q: str) -> Response:
        if self.vulnerable and ("'" in q or '"' in q):   # string-built SQL breaks on quotes
            return Response(500, self._headers(), f"SQL syntax error near '{q}'")
        return Response(200, self._headers(), f"0 results for {q.replace('<', '&lt;')}")
