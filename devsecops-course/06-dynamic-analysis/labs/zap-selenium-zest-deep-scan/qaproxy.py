"""A recording HTTP proxy and a scripted "browser" that drives the app through it.

This stands in for: Selenium/Playwright/Cypress with ``--proxy-server=localhost:8080`` while ZAP
listens as a proxy and records every request the QA test makes. Everything is loopback.
"""

from __future__ import annotations

import http.client
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse


@dataclass(frozen=True)
class Recorded:
    method: str
    url: str
    status: int
    body: str = ""


def _loopback(url: str) -> None:
    if urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        raise ValueError("scope guard: the proxy only forwards to loopback")


class RecordingProxy:
    def __init__(self):
        self.log: list = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _forward(self):
                url = self.path  # a proxy client sends the absolute URL
                _loopback(url)
                n = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(n) if n else None
                p = urlparse(url)
                conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
                fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-connection", "host")}
                conn.request(self.command, p.path + (f"?{p.query}" if p.query else ""), body=body, headers=fwd)
                r = conn.getresponse()
                data = r.read()
                outer.log.append(Recorded(self.command, url, r.status, body.decode() if body else ""))
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection", "server", "date"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
                conn.close()

            do_GET = do_POST = _forward

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def urls(self, method="GET") -> list:
        """Distinct URLs seen, in first-seen order."""
        seen, out = set(), []
        for r in self.log:
            if r.method == method and r.url not in seen:
                seen.add(r.url)
                out.append(r.url)
        return out


class ScriptedBrowser:
    """Plays QA steps through the proxy and keeps cookies like a real browser."""

    def __init__(self, base: str, proxy_port: int):
        self.base = base.rstrip("/")
        self.proxy_port = proxy_port
        self.cookies: dict = {}

    def _request(self, method, path, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
        headers = {}
        body = None
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if data is not None:
            body = urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, self.base + path, body=body, headers=headers)
        r = conn.getresponse()
        r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                self.cookies[name] = rest.split(";")[0]
        loc = r.getheader("Location")
        status = r.status
        conn.close()
        if status in (301, 302) and loc:
            return self._request("GET", loc)
        return status

    def play(self, scenario: dict) -> list:
        results = []
        for step in scenario["steps"]:
            if step["action"] in ("goto", "xhr"):
                results.append((step["action"], step["path"], self._request("GET", step["path"])))
            elif step["action"] == "submit_form":
                results.append((step["action"], step["path"], self._request("POST", step["path"], step["data"])))
            else:
                raise ValueError(f"unknown QA action {step['action']!r}")
        return results

    def cookie_header(self) -> dict:
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())} if self.cookies else {}


def recording_to_zest(recorded: list, title="Recorded from QA run") -> dict:
    """Turn a proxy recording into a Zest-like script (the idea of the real Zest recorder)."""
    stmts = []
    for i, r in enumerate(recorded, 1):
        st = {"index": i, "elementType": "ZestRequest", "method": r.method, "url": r.url.replace(urlparse(r.url).netloc, "{{host}}"),
              "assertions": [{"elementType": "ZestAssertStatusCode", "code": r.status}]}
        if r.body:
            st["data"] = r.body
        stmts.append(st)
    return {"zestVersion": "0.3-simplified", "title": title, "statements": stmts}


def dump(obj) -> str:
    return json.dumps(obj, indent=2)
