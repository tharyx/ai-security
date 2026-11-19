"""A simulated web app: it answers HTTP-like requests in memory. No sockets, nothing listens.

SimApp(vulnerable=False) behaves well. SimApp(vulnerable=True) has the classic mistakes:
no cookie flags, no lockout, user enumeration, predictable session ids, version banners,
missing headers, an exposed .git folder and an unprotected /admin.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

USERS = {"alice": {"password": "correct-horse", "role": "user"},
         "root-admin": {"password": "battery-staple", "role": "admin"}}


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    set_cookies: list = field(default_factory=list)  # raw Set-Cookie header values

    def header(self, name: str):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def cookie(self, name: str):
        """Parse the Set-Cookie for `name` into {'value':..., 'flags': {...}, 'attrs': {...}} or None."""
        for raw in self.set_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if parts[0].split("=", 1)[0] == name:
                flags = {p.lower() for p in parts[1:] if "=" not in p}
                attrs = {p.split("=", 1)[0].lower(): p.split("=", 1)[1] for p in parts[1:] if "=" in p}
                return {"value": parts[0].split("=", 1)[1], "flags": flags, "attrs": attrs}
        return None


class SimApp:
    def __init__(self, vulnerable: bool = False, lockout_threshold: int = 5):
        self.vulnerable = vulnerable
        self.threshold = lockout_threshold
        self.failures: dict = {}
        self.sessions: dict = {}
        self._counter = 0

    # -- helpers
    def _base_headers(self) -> dict:
        if self.vulnerable:
            return {"Server": "Apache/2.4.1 (Ubuntu)", "X-Powered-By": "PHP/5.6.40"}
        return {"Server": "web", "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'", "Cache-Control": "no-store"}

    def _new_session(self, user: str) -> str:
        if self.vulnerable:
            self._counter += 1
            sid = f"sess-{self._counter:04d}"
        else:
            sid = secrets.token_hex(16)
        self.sessions[sid] = user
        return sid

    def _resp(self, status, body="", headers=None, cookies=None) -> Response:
        h = self._base_headers()
        h.update(headers or {})
        return Response(status, h, body, cookies or [])

    # -- the "server"
    def handle(self, method: str, path: str, form: dict | None = None, cookies: dict | None = None) -> Response:
        method, form, cookies = method.upper(), form or {}, cookies or {}
        if path == "/" and method == "GET":
            return self._resp(200, "Welcome to the shop")
        if path == "/health" and method == "GET":
            return self._resp(200, "ok")
        if path == "/login" and method == "POST":
            return self._login(form.get("username", ""), form.get("password", ""))
        if path == "/logout" and method == "POST":
            self.sessions.pop(cookies.get("session", ""), None)
            return self._resp(204, "", cookies=["session=; Max-Age=0; Path=/; HttpOnly; Secure"])
        if path == "/admin" and method == "GET":
            user = self.sessions.get(cookies.get("session", ""))
            if self.vulnerable:
                return self._resp(200, "admin console")
            if not user:
                return self._resp(302, "", {"Location": "/login"})
            if USERS[user]["role"] != "admin":
                return self._resp(403, "forbidden")
            return self._resp(200, "admin console")
        if path.startswith("/.git/"):
            return self._resp(200, "[core]") if self.vulnerable else self._resp(404, "not found")
        return self._resp(404, "not found")

    def _login(self, username: str, password: str) -> Response:
        if not self.vulnerable and self.failures.get(username, 0) >= self.threshold:
            return self._resp(423, "Account locked. Try again later.")
        user = USERS.get(username)
        if user and user["password"] == password:
            self.failures[username] = 0
            sid = self._new_session(username)
            flags = f"session={sid}; Path=/"
            if not self.vulnerable:
                flags += "; HttpOnly; Secure; SameSite=Lax"
            return self._resp(200, f"Hello {username}", cookies=[flags])
        self.failures[username] = self.failures.get(username, 0) + 1
        if self.vulnerable:
            msg = "Wrong password" if user else "Unknown user"
            return self._resp(401, msg)
        return self._resp(401, "Invalid username or password")
