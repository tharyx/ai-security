from pathlib import Path

import pytest

from aisec_lab import load_lab_module

api = load_lab_module(__file__, "mockapi")
scan = load_lab_module(__file__, "apiscan")
SPEC = scan.load_spec(Path(__file__).parent / "fixtures" / "openapi.yaml")
CREDS = {"user": "alice", "password": "alice-demo-pass"}
OTHER = {"orderId": 2}


def test_spec_parsing_finds_all_operations():
    eps = {(e.method, e.path): e for e in scan.endpoints(SPEC)}
    assert set(eps) == {("POST", "/api/v1/login"), ("GET", "/api/v1/products"), ("GET", "/api/v1/orders/{orderId}")}
    assert eps[("GET", "/api/v1/orders/{orderId}")].secured and not eps[("POST", "/api/v1/login")].secured
    assert eps[("GET", "/api/v1/orders/{orderId}")].params == (("orderId", "path", "integer"),)


def test_request_generation_per_endpoint():
    eps = {(e.method, e.path): e for e in scan.endpoints(SPEC)}
    kinds = [k for _, k, _, _ in scan.generate_requests(eps[("GET", "/api/v1/orders/{orderId}")])]
    assert kinds == ["baseline", "no-auth", "bola"]
    kinds = [k for _, k, _, _ in scan.generate_requests(eps[("GET", "/api/v1/products")])]
    assert kinds.count("inject") == 2 and "no-auth" in kinds
    assert [k for _, k, _, _ in scan.generate_requests(eps[("POST", "/api/v1/login")])] == ["baseline"]


def test_weak_api_findings():
    with api.running(False) as srv:
        found, sent = scan.scan(SPEC, srv.base, CREDS, OTHER)
    rules = {f.rule for f in found}
    assert {"API-BOLA", "API-SQLI-ERROR", "API-AUTH-MISSING"} <= rules
    assert sent >= 6


def test_fixed_api_is_clean():
    with api.running(True) as srv:
        found, _ = scan.scan(SPEC, srv.base, CREDS, OTHER)
    assert found == []


def test_bola_fix_returns_403_for_foreign_object():
    import json
    import urllib.error
    import urllib.request

    with api.running(True) as srv:
        _, body = scan._call("POST", srv.base + "/api/v1/login", body={"username": "alice", "password": "alice-demo-pass"})
        auth = {"Authorization": "Bearer " + json.loads(body)["token"]}
        assert scan._call("GET", srv.base + "/api/v1/orders/1", auth)[0] == 200
        assert scan._call("GET", srv.base + "/api/v1/orders/2", auth)[0] == 403


def test_scope_guard():
    with pytest.raises(ValueError):
        scan.scan(SPEC, "http://api.example.test", CREDS, OTHER)


def test_non_openapi3_rejected():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "swagger2.yaml"
        p.write_text("swagger: '2.0'\npaths: {}\n")
        with pytest.raises(ValueError):
            scan.load_spec(p)
