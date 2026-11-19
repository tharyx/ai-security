"""Optional: expose a Server over real HTTP, bound to 127.0.0.1 only, on an ephemeral port.

Shows that the same recon code works over a socket. The server is started and stopped by the
caller (tests use the context manager). It refuses to bind to anything but loopback.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterator

from aisec_lab import load_lab_module

rpc = load_lab_module(__file__, "rpc")


@contextmanager
def serve(server: "rpc.Server", host: str = "127.0.0.1") -> Iterator[str]:
    if host != "127.0.0.1":
        raise ValueError("lab servers bind to 127.0.0.1 only")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else None
            reply = server.handle(body, token)
            if reply is not None and json.loads(reply).get("error", {}).get("code") == rpc.UNAUTHORIZED:
                self.send_response(401)
                self.end_headers()
                return
            if reply is None:
                self.send_response(202)
                self.end_headers()
                return
            data = reply.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:  # keep test output quiet
            pass

    httpd = ThreadingHTTPServer((host, 0), Handler)  # port 0 = the OS picks a free port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{httpd.server_address[1]}/mcp"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def http_transport(url: str) -> Callable[..., str | None]:
    def send(raw: str, token: str | None = None) -> str | None:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=raw.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode()
                return text or None
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return rpc.Server._error(json.loads(raw).get("id"), rpc.UNAUTHORIZED, "Unauthorized")
            raise

    return send
