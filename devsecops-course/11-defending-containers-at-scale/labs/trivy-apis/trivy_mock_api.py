"""A local MOCK of a Trivy server/client split (127.0.0.1 only, no real Trivy).

Concept: `trivy server --listen 127.0.0.1:4954 --token ...` holds the vulnerability DB
and does the scanning; `trivy image --server http://... --token ...` is a thin client
that sends layer/package data and gets results back over an RPC API (Twirp style).
Route names and header names below are modelled on that idea: verify in the Trivy
docs for your version. This mock only returns canned reports.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import error, request

SCAN_PATH = "/twirp/trivy.scanner.v1.Scanner/Scan"
TOKEN_HEADER = "Trivy-Token"


def make_server(reports: dict[str, dict], token: str) -> HTTPServer:
    """reports maps target name -> Trivy JSON report. Port 0 = pick a free port."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep tests quiet
            pass

        def _send(self, code: int, body: dict | str):
            data = (body if isinstance(body, str) else json.dumps(body)).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/healthz":
                return self._send(200, "ok")
            self._send(404, {"error": "not found"})

        def do_POST(self):
            # Always drain the request body first: replying early (e.g. 401) while the
            # body is unread can make Windows reset the connection before the client
            # sees the status code.
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b""
            if self.path != SCAN_PATH:
                return self._send(404, {"error": "not found"})
            if self.headers.get(TOKEN_HEADER) != token:
                return self._send(401, {"error": "unauthenticated"})
            target = json.loads(raw or b"{}").get("target", "")
            if target not in reports:
                return self._send(404, {"error": f"unknown target {target}"})
            self._send(200, reports[target])

    return HTTPServer(("127.0.0.1", 0), Handler)


def serve_in_thread(server: HTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def scan(base_url: str, target: str, token: str) -> tuple[int, dict]:
    """The 'client' half: POST the target, return (status, JSON)."""
    req = request.Request(base_url + SCAN_PATH, data=json.dumps({"target": target}).encode(),
                          headers={"Content-Type": "application/json", TOKEN_HEADER: token})
    try:
        with request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except error.HTTPError as e:
        return e.code, json.loads(e.read())
