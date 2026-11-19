import pytest

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "app")
dast = load_lab_module(__file__, "dast")


@pytest.fixture
def vulnerable():
    srv, base = app.start(fixed=False)
    yield base
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def fixed():
    srv, base = app.start(fixed=True)
    yield base
    srv.shutdown()
    srv.server_close()


def kinds(findings):
    return {(f.kind, f.path) for f in findings}


def test_server_binds_loopback_only(vulnerable):
    assert vulnerable.startswith("http://127.0.0.1:")


def test_crawler_discovers_endpoints_and_params(vulnerable):
    found = dast.crawl(vulnerable)
    assert found["/search"] == {"q"} and found["/user"] == {"id"} and found["/fetch"] == {"url"}


def test_dast_finds_xss_sqli_ssrf(vulnerable):
    k = kinds(dast.scan(vulnerable))
    assert ("reflected-xss", "/search") in k
    assert ("sqli-error", "/user") in k and ("sqli-boolean", "/user") in k
    assert ("ssrf", "/fetch") in k


def test_echoing_page_is_not_reported_as_sqli(vulnerable):
    k = kinds(dast.scan(vulnerable))
    assert ("sqli-boolean", "/search") not in k  # false-positive guard: the page only reflects input
    assert dast.strip_echo("x 1 AND 1=1 y", "1 AND 1=1") == "x  y"


def test_passive_headers_missing_on_vulnerable(vulnerable):
    assert {f.evidence for f in dast.passive_checks(vulnerable)} == {"Content-Security-Policy", "X-Content-Type-Options"}


def test_fixed_app_has_no_findings(fixed):
    assert dast.scan(fixed) == []


def test_fixed_app_still_works_for_normal_use(fixed):
    assert "alice" in dast.get(fixed + "/user?id=1").body
    assert "widgets" in dast.get(fixed + "/search?q=widgets").body
    assert dast.get(fixed + "/fetch?url=http://docs.example/x").status == 200


def test_fixed_app_escapes_marker(fixed):
    body = dast.get(fixed + "/search?q=" + "%3Ccsse7f3a%3E").body
    assert "&lt;csse7f3a&gt;" in body and dast.XSS_MARKER not in body


def test_fixed_app_blocks_internal_fetch(fixed):
    r = dast.get(fixed + "/fetch?url=" + fixed + "/internal/metadata")
    assert r.status == 403 and dast.SSRF_CANARY not in r.body


def test_scanner_refuses_remote_targets():
    with pytest.raises(ValueError):
        dast.scan("http://scanme.example")
    with pytest.raises(ValueError):
        dast.crawl("http://10.0.0.5:8080")
