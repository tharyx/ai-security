"""A tiny web app on 127.0.0.1 for the DAST labs.

``create_server(fixed=False)`` is deliberately weak. ``fixed=True`` is the repaired twin.
Nothing here talks to the network except the loopback interface. The "secret" values are
FAKE canaries built at runtime.

Routes
  /                  home page (static links only; some pages are reachable only through JS)
  /about             static page
  /login (GET/POST)  form login -> session cookie;  /api/login (POST JSON) -> bearer token
  /search?q=         reflected XSS (weak)         -- hidden from a plain spider (JS only)
  /user?id=          SQL injection with verbose error (weak) -- hidden from a plain spider
  /files/            directory listing (weak)
  /.git/HEAD /.env   exposed files (weak)
  /account           needs login (cookie or bearer)
  /account/notes?q=  reflected XSS behind login (weak)
"""

from __future__ import annotations

import html
import json
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERS = {"alice": "alice-demo-pass", "bob": "bob-demo-pass"}  # FAKE demo credentials
FAKE_DB_SECRET = "FAKE-" + "db-pass-" + "0000"  # canary, not a real secret

SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
    con.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [(1, "alice", "alice@example.test"), (2, "bob", "bob@example.test")],
    )
    return con


def make_handler(fixed: bool, sessions: dict):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DemoApp" if fixed else "DemoApp/1.0 Python-http.server/3.11"

        def version_string(self):
            return self.server_version  # fixed app: no interpreter version; weak app leaks it

        def log_message(self, *a):  # keep test output quiet
            pass

        # ---- helpers
        def send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if fixed:
                for k, v in SEC_HEADERS.items():
                    self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def user(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return sessions.get(auth[7:])
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "session" and v in sessions:
                    return sessions[v]
            return None

        def new_session(self, name):
            token = "sess-" + str(len(sessions) + 1) + "-" + name
            sessions[token] = name
            return token

        def esc(self, s):
            return html.escape(s) if fixed else s

        # ---- routes
        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            p = u.path
            if p == "/":
                return self.send(
                    200,
                    "<html><body><h1>Demo shop</h1><a href='/about'>About</a> <a href='/login'>Login</a>"
                    "<script>var menu=['/search?q=','/user?id='];/* built by JS: a plain spider never sees these */</script>"
                    "</body></html>",
                )
            if p == "/about":
                return self.send(200, "<html><body>About us</body></html>")
            if p == "/login":
                return self.send(
                    200,
                    "<form method='post' action='/login'><input name='username'>"
                    "<input name='password' type='password'></form>",
                )
            if p == "/search":
                return self.send(200, f"<html><body>Results for: {self.esc(q.get('q', ''))}</body></html>")
            if p == "/user":
                return self.user_page(q.get("id", "1"))
            if p == "/files/":
                if fixed:
                    return self.send(403, "Forbidden")
                return self.send(
                    200,
                    "<html><title>Index of /files/</title><h1>Index of /files/</h1>"
                    "<a href='backup.sql'>backup.sql</a></html>",
                )
            if p == "/.git/HEAD":
                if fixed:
                    return self.send(404, "Not found")
                return self.send(200, "ref: refs/heads/main\n", "text/plain")
            if p == "/.env":
                if fixed:
                    return self.send(404, "Not found")
                return self.send(200, f"DB_PASSWORD={FAKE_DB_SECRET}\n", "text/plain")
            if p in ("/account", "/account/notes"):
                who = self.user()
                if not who:
                    return self.send(401, "Login required")
                if p == "/account":
                    return self.send(
                        200,
                        f"<html><body>Welcome {html.escape(who)} <a href='/account/notes?q='>Notes</a></body></html>",
                    )
                return self.send(
                    200,
                    f"<html><body>Notes matching: {self.esc(q.get('q', ''))} (user {html.escape(who)})</body></html>",
                )
            return self.send(404, "Not found")

        def user_page(self, uid):
            con = _db()
            try:
                if fixed:
                    if not uid.isdigit():
                        return self.send(400, "Bad id")
                    rows = con.execute("SELECT name, email FROM users WHERE id = ?", (int(uid),)).fetchall()
                else:
                    rows = con.execute(f"SELECT name, email FROM users WHERE id = {uid}").fetchall()
                return self.send(200, f"<html><body>{rows}</body></html>")
            except sqlite3.Error as exc:
                # weak: leaks the engine error text. fixed: generic message.
                if fixed:
                    return self.send(500, "Internal error")
                return self.send(500, f"SQLite error: {exc} while running: SELECT name, email FROM users WHERE id = {uid}")

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode()
            p = urlparse(self.path).path
            if p == "/login":
                f = {k: v[0] for k, v in parse_qs(raw).items()}
                if USERS.get(f.get("username", "")) == f.get("password"):
                    tok = self.new_session(f["username"])
                    flags = "; HttpOnly; SameSite=Strict" if fixed else ""
                    return self.send(302, "", extra={"Set-Cookie": f"session={tok}; Path=/{flags}", "Location": "/account"})
                return self.send(401, "Invalid credentials")
            if p == "/api/login":
                try:
                    d = json.loads(raw)
                except ValueError:
                    return self.send(400, "{}", "application/json")
                if USERS.get(d.get("username", "")) == d.get("password"):
                    tok = self.new_session(d["username"])
                    return self.send(200, json.dumps({"token": tok}), "application/json")
                return self.send(401, json.dumps({"error": "invalid"}), "application/json")
            return self.send(404, "Not found")

    return Handler


class AppServer:
    def __init__(self, fixed: bool = False):
        self.sessions: dict = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fixed, self.sessions))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@contextmanager
def running(fixed: bool = False):
    srv = AppServer(fixed).start()
    try:
        yield srv
    finally:
        srv.stop()
