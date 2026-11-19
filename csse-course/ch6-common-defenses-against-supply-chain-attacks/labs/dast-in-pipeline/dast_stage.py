"""DAST as a pipeline stage against a LOCAL deliberately weak app (127.0.0.1 only) with a scope guard.

The scanner refuses any target that is not loopback. Never point a real scanner at systems you do not own or lack written permission to test.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY = "csse-xss-canary-7731"
REQUIRED_HEADERS = {"Content-Security-Policy": "medium", "X-Content-Type-Options": "low", "Strict-Transport-Security": "low"}


class WeakApp(BaseHTTPRequestHandler):
    """Reflects input unescaped, leaks version and a debug path, sets a weak cookie."""

    server_version = "WeakApp/1.0.3"
    sys_version = ""

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/search":
            body = f"<html>results for {q.get('q', [''])[0]}</html>"  # reflected, unescaped
        elif u.path == "/safe":
            import html
            body = f"<html>results for {html.escape(q.get('q', [''])[0])}</html>"
        elif u.path == "/.git/HEAD":
            body = "ref: refs/heads/main"
        elif u.path == "/error":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last): File app.py line 12 ... (fixture)")
            return
        else:
            body = "<html>home</html>"
        self.send_response(200)
        self.send_header("Set-Cookie", "session=FAKE123; Path=/")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class HardenedApp(WeakApp):
    server_version = "webapp"

    def do_GET(self):
        if self.path.startswith(("/.git", "/error")):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        for k, v in (("Content-Security-Policy", "default-src 'self'"), ("X-Content-Type-Options", "nosniff"),
                     ("Strict-Transport-Security", "max-age=31536000"), ("Set-Cookie", "session=FAKE123; Path=/; HttpOnly; Secure; SameSite=Lax")):
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        import html
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.wfile.write(f"<html>{html.escape(q.get('q', [''])[0])}</html>".encode())


def start_server(handler=WeakApp):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def stop_server(srv):
    srv.shutdown()
    srv.server_close()


def in_scope(base: str) -> bool:
    return urllib.parse.urlparse(base).hostname in ("127.0.0.1", "localhost", "::1")


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def scan(base: str):
    if not in_scope(base):
        raise PermissionError(f"target {base} is out of scope: only loopback targets are allowed in this lab")
    f = []
    status, headers, _ = _get(base + "/")
    for h, sev in REQUIRED_HEADERS.items():
        if h not in headers:
            f.append({"id": "DAST-HEADER", "severity": sev, "detail": f"missing {h}"})
    if "Server" in headers and any(ch.isdigit() for ch in headers["Server"].strip()):
        f.append({"id": "DAST-VERSION-DISCLOSURE", "severity": "low", "detail": f"Server header reveals version: {headers['Server'].strip()}"})
    cookie = headers.get("Set-Cookie", "")
    if cookie and ("HttpOnly" not in cookie or "Secure" not in cookie):
        f.append({"id": "DAST-COOKIE-FLAGS", "severity": "medium", "detail": "session cookie lacks HttpOnly and/or Secure"})
    _, _, body = _get(f"{base}/search?q={urllib.parse.quote('<i>' + CANARY + '</i>')}")
    if f"<i>{CANARY}</i>" in body:
        f.append({"id": "DAST-REFLECTED-XSS", "severity": "high", "detail": "input reflected without encoding (canary markup came back intact)"})
    s, _, _ = _get(base + "/.git/HEAD")
    if s == 200:
        f.append({"id": "DAST-EXPOSED-GIT", "severity": "high", "detail": "/.git/HEAD is publicly readable"})
    s, _, body = _get(base + "/error")
    if s == 500 and "Traceback" in body:
        f.append({"id": "DAST-VERBOSE-ERROR", "severity": "medium", "detail": "stack trace shown to the client"})
    return f


def gate(findings, fail_on=("high",)) -> str:
    return "failed" if any(x["severity"] in fail_on for x in findings) else "passed"
