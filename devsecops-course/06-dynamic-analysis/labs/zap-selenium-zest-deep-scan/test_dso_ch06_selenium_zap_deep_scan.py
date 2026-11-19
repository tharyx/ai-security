import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

HERE = Path(__file__).parent
_APP = str(HERE.parent / "dast-local-app" / "x.py")
app = load_lab_module(_APP, "vulnapp")
prober = load_lab_module(_APP, "prober")
qa = load_lab_module(__file__, "qaproxy")
SCENARIO = json.loads((HERE / "fixtures" / "qa_steps.json").read_text())


@pytest.fixture()
def run():
    with app.running(False) as srv:
        proxy = qa.RecordingProxy().start()
        browser = qa.ScriptedBrowser(srv.base, proxy.port)
        results = browser.play(SCENARIO)
        proxy.stop()
        yield srv, proxy, browser, results


def test_proxy_records_every_request_including_hidden_pages(run):
    srv, proxy, browser, results = run
    paths = [u.replace(srv.base, "") for u in proxy.urls()]
    assert "/search?q=laptop" in paths and "/user?id=1" in paths and "/account/notes?q=meeting" in paths
    assert any(r.method == "POST" and "/login" in r.url for r in proxy.log)


def test_browser_login_sets_session_and_reaches_account(run):
    _, _, browser, results = run
    assert "session" in browser.cookies
    assert ("goto", "/account", 200) in results  # redirect after login was followed


def test_coverage_before_and_after(run):
    srv, proxy, browser, _ = run
    before = prober.Prober(srv.base)
    cov_before = prober.Prober.coverage(sorted(before.spider()))
    urls = [u.replace(srv.base, "") for u in proxy.urls()]
    cov_after = prober.Prober.coverage(urls)
    assert cov_before == set()
    assert cov_after == {("/search", "q"), ("/user", "id"), ("/account/notes", "q")}


def test_qa_driven_scan_finds_more_than_spider(run):
    srv, proxy, browser, _ = run
    spider_only = prober.Prober(srv.base).scan()
    urls = [u.replace(srv.base, "") for u in proxy.urls()]
    deep = prober.Prober(srv.base, browser.cookie_header()).scan(urls)
    assert len(deep) > len(spider_only)
    assert {"REFLECTED-XSS", "SQLI-ERROR"} <= {f.rule for f in deep}
    assert not {"REFLECTED-XSS", "SQLI-ERROR"} & {f.rule for f in spider_only}
    assert any(f.url.endswith("/account/notes?q=") for f in deep)  # only reachable with the session


def test_recording_becomes_zest_like_script(run):
    _, proxy, _, _ = run
    z = qa.recording_to_zest(proxy.log)
    assert len(z["statements"]) == len(proxy.log)
    assert all("{{host}}" in s["url"] for s in z["statements"])
    assert z["statements"][0]["assertions"][0]["code"] == 200


def test_proxy_refuses_non_loopback_targets():
    import http.client

    proxy = qa.RecordingProxy().start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=3)
        try:
            conn.request("GET", "http://example.test/")
            r = conn.getresponse()
            assert r.status >= 500 or r.status == 0
        except (ConnectionError, http.client.RemoteDisconnected, http.client.BadStatusLine):
            pass  # handler raised before replying: also a refusal
        assert proxy.log == []
    finally:
        proxy.stop()


def test_unknown_action_rejected():
    b = qa.ScriptedBrowser("http://127.0.0.1:9", 9)
    with pytest.raises(ValueError):
        b.play({"steps": [{"action": "teleport"}]})
