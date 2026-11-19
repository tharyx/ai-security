"""A SIMULATED local agent gateway with switchable insecure defaults.

This is NOT OpenClaw and contains no OpenClaw code. It copies the *class* of
mistake that was widely reported: a local agent gateway whose defaults are too
open (broad bind in config, no auth, permissive origin handling, tokens
reachable by a web page).

Safety: the socket ALWAYS binds to 127.0.0.1 on an ephemeral port, even when the
config says "0.0.0.0". The config value is only *data* that the auditor reads.
All tokens are FAKE.
"""

from __future__ import annotations

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_TOKEN = "FAKE-GATEWAY-TOKEN-0000"
PATCHED_VERSION = (2026, 2, 0)  # fictional "fixed" version for the lab

INSECURE_CONFIG = {
    "version": "2026.1.0",
    "bind": "0.0.0.0",            # config value only; the lab socket stays on loopback
    "auth_token": None,            # no authentication
    "allowed_origins": ["*"],      # any web page may talk to the gateway
    "expose_token_in_api": True,   # /api/session hands the token to any caller
    "tls": False,
}

HARDENED_CONFIG = {
    "version": "2026.2.0",
    "bind": "127.0.0.1",
    "auth_token": FAKE_TOKEN,
    "allowed_origins": ["http://127.0.0.1"],
    "expose_token_in_api": False,
    "tls": False,                  # loopback only; use a reverse proxy with TLS for remote access
}


def make_config(**overrides) -> dict:
    cfg = copy.deepcopy(INSECURE_CONFIG)
    cfg.update(overrides)
    return cfg


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep tests quiet
        pass

    def _send(self, code: int, body: dict, origin: str | None = None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        cfg = self.server.cfg
        if origin is not None and ("*" in cfg["allowed_origins"] or origin in cfg["allowed_origins"]):
            self.send_header("Access-Control-Allow-Origin", "*" if "*" in cfg["allowed_origins"] else origin)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        cfg = self.server.cfg
        origin = self.headers.get("Origin")
        # Origin check: a browser always sends Origin on cross-site requests.
        if origin is not None and "*" not in cfg["allowed_origins"] and origin not in cfg["allowed_origins"]:
            return self._send(403, {"error": "origin not allowed"})
        # Authentication
        if cfg["auth_token"] is not None:
            if self.headers.get("Authorization") != f"Bearer {cfg['auth_token']}":
                return self._send(401, {"error": "auth required"}, origin)
        if self.path == "/api/session":
            body = {"session": "sim-session", "gateway": "simulated"}
            if cfg["expose_token_in_api"]:
                body["token"] = cfg["auth_token"] or FAKE_TOKEN
            return self._send(200, body, origin)
        if self.path == "/api/tools":
            return self._send(200, {"tools": ["shell.run", "files.read"]}, origin)
        return self._send(404, {"error": "not found"}, origin)


class SimGateway:
    """Context manager: start a loopback-only HTTP server with the given config."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.httpd: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def __enter__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)  # ALWAYS loopback
        self.httpd.cfg = self.cfg
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
