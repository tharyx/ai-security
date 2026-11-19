"""A tiny LOCAL web app with deliberate SQLi, reflected XSS and SSRF sinks (vulnerable) and a fixed twin.

Binds to 127.0.0.1 only, on an ephemeral port. Never expose it. Data are fake. The "internal metadata"
route stands for a cloud metadata or admin service that only the server should reach.
"""

from __future__ import annotations

import html
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INTERNAL_SECRET = "FAKE-INTERNAL-CRED-7f3a9c"
ALLOWED_FETCH_HOSTS = {"docs.example"}
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))

INDEX = """<html><body><h1>Demo shop</h1>
<a href="/search?q=widgets">search</a> <a href="/user?id=1">user 1</a>
<a href="/fetch?url=http://docs.example/readme">preview a link</a>
<form action="/search" method="get"><input name="q"></form>
</body></html>"""


def make_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    return db


def create_server(fixed: bool = False) -> ThreadingHTTPServer:
    db = make_db()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep test output quiet
            pass

        def send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if fixed:
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            u = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            if u.path == "/":
                return self.send(200, INDEX)
            if u.path == "/search":
                term = q.get("q", "")
                shown = html.escape(term) if fixed else term  # VULN (vulnerable app): reflected unescaped
                return self.send(200, f"<html><body><p>Results for {shown}</p></body></html>")
            if u.path == "/user":
                return self.user(q.get("id", ""))
            if u.path == "/fetch":
                return self.fetch(q.get("url", ""))
            if u.path == "/internal/metadata":
                return self.send(200, f"role=admin token={INTERNAL_SECRET}", "text/plain")
            self.send(404, "not found")

        def user(self, uid: str) -> None:
            if fixed:
                try:
                    n = int(uid)
                except ValueError:
                    return self.send(400, "invalid id")
                with lock:
                    rows = db.execute("SELECT name FROM users WHERE id = ?", (n,)).fetchall()
                return self.send(200, "users: " + ",".join(r[0] for r in rows))
            try:
                with lock:  # VULN: string concatenation into SQL, and the database error is shown to the client
                    rows = db.execute("SELECT name FROM users WHERE id = " + uid).fetchall()
            except sqlite3.Error as e:
                return self.send(500, f"database error: {e}")
            self.send(200, "users: " + ",".join(r[0] for r in rows))

        def fetch(self, url: str) -> None:
            if fixed:
                host = urllib.parse.urlparse(url).hostname
                if host not in ALLOWED_FETCH_HOSTS:
                    return self.send(403, "host not allowed")
                return self.send(200, f"(simulated preview of {html.escape(url)})")
            try:  # VULN: the server fetches whatever URL the client gives, including internal ones
                with _NO_PROXY.open(url, timeout=3) as r:
                    return self.send(200, r.read(2000).decode("utf-8", "replace"), "text/plain")
            except (urllib.error.URLError, ValueError, OSError) as e:
                return self.send(502, f"fetch failed: {type(e).__name__}")

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def start(fixed: bool = False) -> tuple[ThreadingHTTPServer, str]:
    srv = create_server(fixed)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
