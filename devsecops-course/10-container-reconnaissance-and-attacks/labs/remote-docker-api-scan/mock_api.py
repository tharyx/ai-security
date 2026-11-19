"""A mock Docker Engine API bound to 127.0.0.1 only. It answers /_ping, /version, /info and /containers/json.

auth_token=None  -> NO authentication (like an exposed tcp://0.0.0.0:2375 daemon).
auth_token="x"   -> requires the header 'X-Api-Key: x', else 401 (stands in for TLS client certificates).
The data is fake. This server never starts anything and refuses to bind anywhere but loopback.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE = {
    "/_ping": "OK",
    "/version": {"Version": "27.3.1-mock", "ApiVersion": "1.47", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.8.0-mock"},
    "/info": {"Name": "mock-host", "ServerVersion": "27.3.1-mock", "Containers": 2, "SecurityOptions": ["name=seccomp,profile=builtin"]},
    "/containers/json": [
        {"Id": "aaaaaaaaaaaa", "Names": ["/shop-web"], "Image": "nginx:1.27", "State": "running"},
        {"Id": "bbbbbbbbbbbb", "Names": ["/shop-db"], "Image": "postgres:16", "State": "running"},
    ],
}


class MockDockerServer:
    def __init__(self, port: int = 0, auth_token: str | None = None):
        token = auth_token

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if token is not None and self.headers.get("X-Api-Key") != token:
                    return self._send(401, {"message": "authentication required"})
                path = self.path.split("?")[0]
                if path in FAKE:
                    return self._send(200, FAKE[path])
                self._send(404, {"message": "page not found"})

            def _send(self, code, body):
                raw = (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/plain" if isinstance(body, str) else "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):  # keep test output quiet
                pass

        self.httpd = HTTPServer(("127.0.0.1", port), H)    # loopback only, never 0.0.0.0
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
