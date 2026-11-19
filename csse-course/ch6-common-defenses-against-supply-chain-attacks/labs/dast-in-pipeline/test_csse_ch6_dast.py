"""Tests for the DAST stage (local servers only, bound to 127.0.0.1)."""

import pytest

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "dast_stage")


@pytest.fixture
def weak():
    srv, base = d.start_server(d.WeakApp)
    yield base
    d.stop_server(srv)


@pytest.fixture
def hardened():
    srv, base = d.start_server(d.HardenedApp)
    yield base
    d.stop_server(srv)


def ids(findings):
    return {f["id"] for f in findings}


def test_server_binds_to_loopback(weak):
    assert weak.startswith("http://127.0.0.1:")


def test_weak_app_findings(weak):
    f = d.scan(weak)
    assert {"DAST-HEADER", "DAST-VERSION-DISCLOSURE", "DAST-COOKIE-FLAGS", "DAST-REFLECTED-XSS", "DAST-EXPOSED-GIT", "DAST-VERBOSE-ERROR"} <= ids(f)


def test_gate_fails_on_weak_app(weak):
    assert d.gate(d.scan(weak)) == "failed"


def test_hardened_app_is_clean_for_headers_cookie_and_xss(hardened):
    f = d.scan(hardened)
    assert not ({"DAST-HEADER", "DAST-COOKIE-FLAGS", "DAST-REFLECTED-XSS", "DAST-VERSION-DISCLOSURE"} & ids(f))


def test_scope_guard_refuses_non_loopback():
    with pytest.raises(PermissionError):
        d.scan("http://app.example")
    with pytest.raises(PermissionError):
        d.scan("http://192.0.2.10:8080")


def test_in_scope_helper():
    assert d.in_scope("http://127.0.0.1:1234") and d.in_scope("http://localhost:80")
    assert not d.in_scope("https://example.com")


def test_gate_threshold_option():
    f = [{"id": "x", "severity": "medium", "detail": ""}]
    assert d.gate(f) == "passed" and d.gate(f, fail_on=("medium", "high")) == "failed"


def test_safe_endpoint_escapes_input(weak):
    _, _, body = d._get(weak + "/safe?q=%3Cb%3Ex")
    assert "&lt;b&gt;" in body


def test_hardened_app_passes_the_gate(hardened):
    assert d.gate(d.scan(hardened)) == "passed"
