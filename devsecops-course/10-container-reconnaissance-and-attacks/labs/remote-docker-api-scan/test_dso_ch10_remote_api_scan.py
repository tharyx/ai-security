import socket

import pytest
from aisec_lab import load_lab_module

api = load_lab_module(__file__, "mock_api")
sc = load_lab_module(__file__, "scanner")


def test_unauthenticated_api_detected():
    with api.MockDockerServer() as srv:
        r = sc.probe("127.0.0.1", srv.port)
    assert r["state"] == "UNAUTHENTICATED Docker API"
    assert r["version"] == "27.3.1-mock"
    assert r["containers"] == ["shop-web", "shop-db"]
    assert "root on the host" in r["impact"]


def test_authenticated_api_reported_as_auth_required():
    with api.MockDockerServer(auth_token="k-canary") as srv:
        r = sc.probe("127.0.0.1", srv.port)
    assert r["state"] == "auth required" and "containers" not in r


def test_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert sc.probe("127.0.0.1", port)["state"] == "closed"


@pytest.mark.parametrize("host", ["8.8.8.8", "203.0.113.5", "10.0.0.5", "example.com", "0.0.0.0"])
def test_non_loopback_refused(host):
    with pytest.raises(sc.RefusedTarget):
        sc.check_target(host)


def test_scan_reports_refusal_without_connecting():
    out = sc.scan([("203.0.113.10", 2375)])
    assert out[0]["state"] == "REFUSED"


def test_server_binds_loopback_only():
    with api.MockDockerServer() as srv:
        assert srv.httpd.server_address[0] == "127.0.0.1"


def test_non_docker_service_not_flagged():
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"hi")
        def log_message(self, *a): pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        r = sc.probe("127.0.0.1", httpd.server_address[1])
    finally:
        httpd.shutdown(); httpd.server_close()
    assert r["state"] == "open, not a Docker API"
