"""Toy shop for chapter 01: VulnerableShop versus SecureShop.

Everything runs in-process. There is no socket, no real network call and no shell:
- ``fake_fetch`` simulates the network (including a FAKE cloud-metadata canary) for SSRF.
- ``FakeShell`` simulates how /bin/sh would split a command line (it never runs anything).
- ``FakeExec`` simulates an argv-style process start without a shell.

Each handler in ``VulnerableShop`` has a matching override in ``SecureShop`` so you can read
the bug and the fix side by side. Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import shlex
import sqlite3
import traceback
from urllib.parse import parse_qs, urlsplit

Response = tuple  # (status: int, headers: dict, body: str)

# --------------------------------------------------------------------------------------
# Fake infrastructure (simulations only)
# --------------------------------------------------------------------------------------

# Built from pieces at runtime and labelled FAKE so nothing looks like a real credential.
FAKE_METADATA_CANARY = "-".join(["FAKE", "CANARY", "metadata", "role", "credentials"])
PARTNER_HOST = "stock.partner.example"


def fake_fetch(url: str) -> tuple:
    """Simulated HTTP GET. Returns (status, body). No packet ever leaves the process."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host == PARTNER_HOST:
        return 200, json.dumps({"sku": 101, "in_stock": 7})
    if host == "169.254.169.254":  # link-local cloud metadata address (simulated)
        return 200, json.dumps({"Code": "Success", "Token": FAKE_METADATA_CANARY})
    if host in ("localhost", "127.0.0.1") and parts.path.startswith("/admin"):
        return 200, "internal admin panel (simulated, no auth because 'only localhost can reach it')"
    return 404, "unknown host (simulated network)"


class FakeShell:
    """Shows what /bin/sh WOULD run for a command line. Never executes anything."""

    SEPARATORS = {";", "&&", "||", "|", "&"}
    SUBST = re.compile(r"\$\(([^)]*)\)|`([^`]*)`")

    def __init__(self) -> None:
        self.executed: list = []

    def run(self, cmdline: str) -> str:
        commands = []
        for m in self.SUBST.finditer(cmdline):  # command substitution runs first in a real shell
            inner = (m.group(1) or m.group(2) or "").strip()
            if inner:
                commands.append(inner.split())
        lex = shlex.shlex(cmdline.replace("\n", ";"), posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        current: list = []
        for tok in lex:
            if tok in self.SEPARATORS:
                if current:
                    commands.append(current)
                current = []
            else:
                current.append(tok)
        if current:
            commands.append(current)
        self.executed.extend(commands)
        out = []
        for argv in commands:
            if argv and argv[0] == "ping":
                out.append(f"PING {argv[-1]}: 1 packet transmitted (simulated)")
            else:
                out.append("[simulated] would run: " + " ".join(argv))
        return "\n".join(out)


class FakeExec:
    """Simulates subprocess.run([...], shell=False): one program, arguments passed literally."""

    def __init__(self) -> None:
        self.executed: list = []

    def run_argv(self, argv: list) -> str:
        self.executed.append(list(argv))
        return f"PING {argv[-1]}: 1 packet transmitted (simulated, argv mode)"


# --------------------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------------------

TOY_SALT = "toy-shop-lab-salt"  # toy only: real apps use a per-user salt and Argon2id/scrypt


def toy_hash(password: str) -> str:
    return hashlib.sha256((TOY_SALT + password).encode()).hexdigest()


def build_db(admin_password: str) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
                            email TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE reviews (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, text TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, address TEXT);
        """
    )
    users = [
        (1, "alice", toy_hash("alice-lab-pw"), "alice@shop.example", "customer"),
        (2, "bob", toy_hash("bob-lab-pw"), "bob@shop.example", "customer"),
        (3, "admin", toy_hash(admin_password), "admin@shop.example", "admin"),
    ]
    db.executemany("INSERT INTO users VALUES (?,?,?,?,?)", users)
    db.executemany("INSERT INTO products VALUES (?,?,?)",
                   [(1, "Blue mug", 9.5), (2, "Red mug", 9.5), (3, "Tea pot", 24.0)])
    db.executemany("INSERT INTO orders VALUES (?,?,?,?)",
                   [(1, 1, "Blue mug", "12 Lake Road, Pune"), (2, 2, "Tea pot", "7 Hill Street, Kochi")])
    db.commit()
    return db


def parse_form(body: str) -> dict:
    return {k: v[0] for k, v in parse_qs(body or "", keep_blank_values=True).items()}


# --------------------------------------------------------------------------------------
# Vulnerable app
# --------------------------------------------------------------------------------------


class VulnerableShop:
    """Deliberately vulnerable. Every bug is labelled VULN in a comment."""

    ADMIN_PASSWORD = "admin"  # VULN: default credentials (A07 / misconfiguration)

    def __init__(self) -> None:
        self.db = build_db(self.ADMIN_PASSWORD)
        self.sessions: dict = {}  # token -> {"user_id":..., "csrf":...}
        self.shell = FakeShell()
        self.exec = FakeExec()
        self.fetch_log: list = []

    # ---- plumbing -------------------------------------------------------------------
    def base_headers(self) -> dict:
        # VULN: version banner, no CSP, no nosniff, no HSTS, no Referrer-Policy
        return {"Content-Type": "text/html; charset=utf-8", "Server": "ToyShop/0.9 Python/3.11"}

    def cookie_attrs(self) -> str:
        return "Path=/"  # VULN: no HttpOnly, no Secure, no SameSite

    def current_user(self, headers: dict):
        cookie = headers.get("cookie", "")
        m = re.search(r"session=([A-Za-z0-9_-]+)", cookie)
        if not m or m.group(1) not in self.sessions:
            return None
        uid = self.sessions[m.group(1)]["user_id"]
        row = self.db.execute("SELECT id, username, email, role FROM users WHERE id = ?", (uid,)).fetchone()
        return {"id": row[0], "username": row[1], "email": row[2], "role": row[3],
                "session": m.group(1)}

    def handle(self, method: str, path: str, headers: dict | None = None, body: str = "") -> Response:
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        parts = urlsplit(path)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        try:
            return self.route(method.upper(), parts.path, query, headers, body)
        except Exception:  # noqa: BLE001 - the error page is part of the lesson
            return self.error_page(traceback.format_exc())

    def error_page(self, tb: str) -> Response:
        # VULN: stack trace, file paths and SQL leak to the client
        return 500, self.base_headers(), "<h1>Internal Server Error</h1><pre>" + tb + "</pre>"

    def route(self, method, path, query, headers, body) -> Response:
        if method == "GET" and path == "/":
            return 200, self.base_headers(), "<h1>Toy Shop</h1><a href='/search?q=mug'>Search</a>"
        if method == "POST" and path == "/login":
            return self.login(parse_form(body))
        if method == "GET" and path == "/search":
            return self.search(query.get("q", ""))
        m = re.fullmatch(r"/product/(\d+)", path)
        if method == "GET" and m:
            return self.product(int(m.group(1)))
        m = re.fullmatch(r"/product/(\d+)/review", path)
        if method == "POST" and m:
            return self.add_review(int(m.group(1)), headers, parse_form(body))
        if method == "GET" and path == "/account":
            return self.account(headers)
        if method == "POST" and path == "/account/email":
            return self.change_email(headers, parse_form(body))
        if method == "GET" and path == "/stock":
            return self.stock(query.get("url", ""))
        if method == "GET" and path == "/tools/ping":
            return self.ping(query.get("host", ""))
        m = re.fullmatch(r"/orders/([^/]+)", path)
        if method == "GET" and m:
            return self.order(m.group(1), headers)
        if method == "GET" and path == "/logout":
            return self.logout(query.get("next", "/"))
        if method == "GET" and path == "/debug":
            return self.debug()
        if method == "GET" and path == "/static/":
            return self.static_index()
        return 404, self.base_headers(), "not found"

    # ---- features -------------------------------------------------------------------
    def login(self, form: dict) -> Response:
        user, pw = form.get("username", ""), form.get("password", "")
        # VULN (SQL injection): user input concatenated into SQL. "admin'--" skips the password check.
        sql = f"SELECT id FROM users WHERE username = '{user}' AND password_hash = '{toy_hash(pw)}'"
        row = self.db.execute(sql).fetchone()
        if not row:
            return 401, self.base_headers(), "login failed"
        return self.start_session(row[0])

    def start_session(self, user_id: int) -> Response:
        token = secrets.token_urlsafe(16)
        self.sessions[token] = {"user_id": user_id, "csrf": secrets.token_urlsafe(16)}
        h = self.base_headers()
        h["Set-Cookie"] = f"session={token}; {self.cookie_attrs()}"
        return 200, h, "welcome"

    def search(self, q: str) -> Response:
        # VULN (SQL injection): string building. VULN (reflected XSS): q echoed without encoding.
        sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
        rows = self.db.execute(sql).fetchall()
        items = "".join(f"<li>{r[1]} - {r[2]}</li>" for r in rows)
        return 200, self.base_headers(), f"<p>Results for {q}</p><ul>{items}</ul>"

    def product(self, pid: int) -> Response:
        row = self.db.execute("SELECT name, price FROM products WHERE id = ?", (pid,)).fetchone()
        if not row:
            return 404, self.base_headers(), "no such product"
        reviews = self.db.execute("SELECT author, text FROM reviews WHERE product_id = ?", (pid,)).fetchall()
        # VULN (stored XSS): review text rendered as raw HTML
        rv = "".join(f"<div class='review'><b>{a}</b>: {t}</div>" for a, t in reviews)
        return 200, self.base_headers(), f"<h2>{row[0]}</h2>{rv}"

    def add_review(self, pid: int, headers: dict, form: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        self.db.execute("INSERT INTO reviews (product_id, author, text) VALUES (?,?,?)",
                        (pid, user["username"], form.get("text", "")))
        return 201, self.base_headers(), "review saved"

    def account(self, headers: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        return 200, self.base_headers(), (
            f"<p>Email: {user['email']}</p><form method=POST action=/account/email>"
            "<input name=email></form>")

    def change_email(self, headers: dict, form: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        # VULN (CSRF): no anti-CSRF token and no Origin check; the cookie alone authorizes it.
        self.db.execute("UPDATE users SET email = ? WHERE id = ?", (form.get("email", ""), user["id"]))
        return 200, self.base_headers(), "email changed"

    def stock(self, url: str) -> Response:
        # VULN (SSRF): the server fetches ANY URL the client gives it.
        self.fetch_log.append(url)
        status, body = fake_fetch(url)
        return status, self.base_headers(), body

    def ping(self, host: str) -> Response:
        # VULN (command injection): input placed in a shell command line.
        out = self.shell.run(f"ping -c 1 {host}")
        return 200, self.base_headers(), "<pre>" + out + "</pre>"

    def order(self, oid: str, headers: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        # VULN (IDOR / BOLA): no owner check. Also int() on bad input raises -> verbose error page.
        row = self.db.execute("SELECT id, item, address FROM orders WHERE id = ?", (int(oid),)).fetchone()
        if not row:
            return 404, self.base_headers(), "no such order"
        return 200, self.base_headers(), f"order {row[0]}: {row[1]} to {row[2]}"

    def logout(self, nxt: str) -> Response:
        # VULN (open redirect): sends the user wherever ?next= says.
        h = self.base_headers()
        h["Location"] = nxt
        return 302, h, ""

    def debug(self) -> Response:
        # VULN (misconfiguration): debug endpoint left on in production.
        cfg = {"DEBUG": True, "DB": "sqlite::memory:", "SECRET_KEY": "FAKE-" + "debug-key"}
        return 200, self.base_headers(), json.dumps(cfg)

    def static_index(self) -> Response:
        # VULN (misconfiguration): directory listing exposes a backup file.
        return 200, self.base_headers(), "<h1>Index of /static/</h1><a>app.css</a><a>backup.sql</a>"


# --------------------------------------------------------------------------------------
# Secure app: same features, fixed
# --------------------------------------------------------------------------------------

HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")


def safe_next(nxt: str) -> str:
    """Allow only local, path-absolute redirects. Everything else falls back to '/'."""
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        return "/"
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc:
        return "/"
    return nxt


def ssrf_allowed(url: str) -> bool:
    """Exact-host allowlist on the PARSED url: https only, default port, no user-info."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (parts.scheme == "https" and (parts.hostname or "") == PARTNER_HOST
            and port in (None, 443) and parts.username is None and parts.password is None)


def naive_prefix_check(url: str) -> bool:
    """A common WRONG fix: string prefix match. 'https://stock.partner.example@169.254.169.254/' passes."""
    return url.startswith("https://" + PARTNER_HOST)


class SecureShop(VulnerableShop):
    ADMIN_PASSWORD = "-".join(["long", "unique", "lab", "passphrase", "for", "admin"])

    def base_headers(self) -> dict:
        return {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; "
                                       "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Cache-Control": "no-store",
        }

    def cookie_attrs(self) -> str:
        return "Path=/; HttpOnly; Secure; SameSite=Lax"

    def error_page(self, tb: str) -> Response:
        ref = secrets.token_hex(4)  # log tb server-side with this id; show only the id
        return 500, self.base_headers(), f"Something went wrong. Reference: {ref}"

    def login(self, form: dict) -> Response:
        row = self.db.execute("SELECT id, password_hash FROM users WHERE username = ?",
                              (form.get("username", ""),)).fetchone()
        if not row or not hmac.compare_digest(row[1], toy_hash(form.get("password", ""))):
            return 401, self.base_headers(), "login failed"
        return self.start_session(row[0])

    def search(self, q: str) -> Response:
        rows = self.db.execute("SELECT id, name, price FROM products WHERE name LIKE ?",
                               (f"%{q}%",)).fetchall()
        items = "".join(f"<li>{html.escape(r[1])} - {r[2]}</li>" for r in rows)
        return 200, self.base_headers(), f"<p>Results for {html.escape(q)}</p><ul>{items}</ul>"

    def product(self, pid: int) -> Response:
        row = self.db.execute("SELECT name, price FROM products WHERE id = ?", (pid,)).fetchone()
        if not row:
            return 404, self.base_headers(), "no such product"
        reviews = self.db.execute("SELECT author, text FROM reviews WHERE product_id = ?", (pid,)).fetchall()
        rv = "".join(f"<div class='review'><b>{html.escape(a)}</b>: {html.escape(t)}</div>" for a, t in reviews)
        return 200, self.base_headers(), f"<h2>{html.escape(row[0])}</h2>{rv}"

    def account(self, headers: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        token = self.sessions[user["session"]]["csrf"]
        return 200, self.base_headers(), (
            f"<p>Email: {html.escape(user['email'])}</p><form method=POST action=/account/email>"
            f"<input type=hidden name=csrf_token value='{token}'><input name=email></form>")

    def change_email(self, headers: dict, form: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        origin = headers.get("origin")
        if origin is not None and origin != "https://shop.example":
            return 403, self.base_headers(), "cross-site request blocked"
        expected = self.sessions[user["session"]]["csrf"]
        if not hmac.compare_digest(form.get("csrf_token", ""), expected):
            return 403, self.base_headers(), "missing or invalid CSRF token"
        self.db.execute("UPDATE users SET email = ? WHERE id = ?", (form.get("email", ""), user["id"]))
        return 200, self.base_headers(), "email changed"

    def stock(self, url: str) -> Response:
        if not ssrf_allowed(url):
            return 400, self.base_headers(), "url not allowed"
        self.fetch_log.append(url)
        status, body = fake_fetch(url)
        return status, self.base_headers(), html.escape(body)

    def ping(self, host: str) -> Response:
        if not HOST_RE.fullmatch(host):
            return 400, self.base_headers(), "invalid host"
        out = self.exec.run_argv(["ping", "-c", "1", host])  # no shell at all
        return 200, self.base_headers(), "<pre>" + html.escape(out) + "</pre>"

    def order(self, oid: str, headers: dict) -> Response:
        user = self.current_user(headers)
        if not user:
            return 401, self.base_headers(), "login required"
        if not oid.isdigit():
            return 400, self.base_headers(), "bad order id"
        # Owner check in the query: like adding WHERE user_id = :me (or an Oracle VPD policy).
        row = self.db.execute("SELECT id, item, address FROM orders WHERE id = ? AND user_id = ?",
                              (int(oid), user["id"])).fetchone()
        if not row:
            return 404, self.base_headers(), "no such order"  # 404, not 403: do not confirm it exists
        return 200, self.base_headers(), html.escape(f"order {row[0]}: {row[1]} to {row[2]}")

    def logout(self, nxt: str) -> Response:
        h = self.base_headers()
        h["Location"] = safe_next(nxt)
        return 302, h, ""

    def debug(self) -> Response:
        return 404, self.base_headers(), "not found"

    def static_index(self) -> Response:
        return 403, self.base_headers(), "directory listing disabled"


# --------------------------------------------------------------------------------------
# A tiny DAST-style misconfiguration probe (like a baseline scan, but in-process)
# --------------------------------------------------------------------------------------

REQUIRED_HEADERS = ["Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security",
                    "Referrer-Policy"]


def misconfig_scan(app) -> list:
    findings = []
    status, h, _ = app.handle("GET", "/")
    for name in REQUIRED_HEADERS:
        if name not in h:
            findings.append(f"MISSING_HEADER:{name}")
    if re.search(r"\d+\.\d+", h.get("Server", "")):
        findings.append("SERVER_VERSION_BANNER")
    if app.handle("GET", "/debug")[0] == 200:
        findings.append("DEBUG_ENDPOINT_ENABLED")
    if "Index of" in app.handle("GET", "/static/")[2]:
        findings.append("DIRECTORY_LISTING")
    status, h, _ = app.handle("POST", "/login", body="username=admin&password=admin")
    if status == 200:
        findings.append("DEFAULT_CREDENTIALS")
    status, h, _ = app.handle("POST", "/login", body="username=alice&password=alice-lab-pw")
    cookie = h.get("Set-Cookie", "")
    for flag in ("HttpOnly", "Secure", "SameSite"):
        if flag not in cookie:
            findings.append(f"COOKIE_WITHOUT_{flag.upper()}")
    token = cookie.split(";")[0]
    if "Traceback" in app.handle("GET", "/orders/abc", {"Cookie": token})[2]:
        findings.append("VERBOSE_ERRORS")
    return findings


def login_cookie(app, username: str, password: str) -> str:
    status, h, _ = app.handle("POST", "/login", body=f"username={username}&password={password}")
    assert status == 200, f"login failed for {username}"
    return h["Set-Cookie"].split(";")[0]
