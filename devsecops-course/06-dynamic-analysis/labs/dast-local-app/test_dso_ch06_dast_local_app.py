import pytest

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "vulnapp")
prober = load_lab_module(__file__, "prober")

HIDDEN = ["/search?q=", "/user?id="]


@pytest.fixture(scope="module")
def weak_findings():
    with app.running(False) as srv:
        p = prober.Prober(srv.base)
        return p.scan(HIDDEN)


def rules(findings):
    return {f.rule for f in findings}


def test_weak_app_has_every_planted_issue(weak_findings):
    assert {"REFLECTED-XSS", "SQLI-ERROR", "MISSING-HEADER", "EXPOSED-FILE", "DIR-LISTING", "VERSION-DISCLOSURE"} <= rules(weak_findings)


def test_exposed_git_and_env_are_found(weak_findings):
    urls = {f.url.rsplit("/", 1)[-1] for f in weak_findings if f.rule == "EXPOSED-FILE"}
    assert {"HEAD", ".env"} <= urls


def test_fixed_app_is_clean():
    with app.running(True) as srv:
        findings = prober.Prober(srv.base).scan(HIDDEN)
    assert findings == []


def test_plain_spider_misses_js_only_pages():
    with app.running(False) as srv:
        p = prober.Prober(srv.base)
        seen = p.spider()
        assert "/about" in seen and "/login" in seen
        assert not any(u.startswith("/search") or u.startswith("/user") for u in seen)
        assert [f for f in p.scan() if f.rule in ("REFLECTED-XSS", "SQLI-ERROR")] == []


def test_scope_guard_refuses_non_loopback():
    with pytest.raises(ValueError):
        prober.Prober("http://example.test")


def test_servers_are_really_stopped():
    import urllib.error
    import urllib.request

    with app.running(False) as srv:
        base = srv.base
    with pytest.raises((urllib.error.URLError, ConnectionError, OSError)):
        urllib.request.urlopen(base + "/", timeout=1)


def test_login_cookie_and_bearer_both_work():
    import json
    import urllib.parse
    import urllib.request

    with app.running(False) as srv:
        data = json.dumps({"username": "alice", "password": "alice-demo-pass"}).encode()
        r = urllib.request.urlopen(urllib.request.Request(srv.base + "/api/login", data=data), timeout=5)
        token = json.loads(r.read())["token"]
        p = prober.Prober(srv.base, {"Authorization": "Bearer " + token})
        assert p.get("/account")[0] == 200
        assert prober.Prober(srv.base).get("/account")[0] == 401
        form = urllib.parse.urlencode({"username": "alice", "password": "alice-demo-pass"}).encode()
        assert form  # form login is exercised in the zap-auth-and-zest lab
