import copy
import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

HERE = Path(__file__).parent
_APP = str(HERE.parent / "dast-local-app" / "x.py")
app = load_lab_module(_APP, "vulnapp")
prober = load_lab_module(_APP, "prober")
zest = load_lab_module(__file__, "zest")
SCRIPT = json.loads((HERE / "fixtures" / "login.zest.json").read_text())
ENV = {"APP_PASSWORD": "alice-demo-pass"}


def test_zest_script_logs_in_and_extracts_variables():
    with app.running(False) as srv:
        res = zest.run_script(SCRIPT, srv.base)
    assert res.passed
    assert res.variables["token"].startswith("sess-")
    assert res.variables["notes_link"] == "/account/notes?q="


def test_failed_assertion_stops_the_script():
    bad = copy.deepcopy(SCRIPT)
    bad["variables"]["pass"] = "wrong-password-demo"
    with app.running(False) as srv:
        res = zest.run_script(bad, srv.base)
    assert not res.passed
    assert any("expected 200, got 401" in s.detail for s in res.steps)
    assert not any("ZestAssignFromJson" in s.summary or s.summary.startswith("token") for s in res.steps)


def test_variable_override_wins():
    with app.running(False) as srv:
        res = zest.run_script(SCRIPT, srv.base, {"user": "bob", "pass": "bob-demo-pass"})
    assert res.passed and res.variables["token"].endswith("-bob")


def test_unsupported_statement_is_reported():
    with app.running(False) as srv:
        with pytest.raises(zest.ZestError):
            zest.run_script({"statements": [{"elementType": "ZestLoopInteger"}]}, srv.base)


def test_zest_refuses_non_loopback():
    with pytest.raises(zest.ZestError):
        zest.run_script({"statements": [{"elementType": "ZestRequest", "method": "GET", "url": "http://example.test/"}]}, "x")


def test_authenticated_page_only_scanned_with_session():
    with app.running(False) as srv:
        res = zest.run_script(SCRIPT, srv.base)
        anon = prober.Prober(srv.base).scan(["/account/notes?q="])
        authed = prober.Prober(srv.base, {"Authorization": "Bearer " + res.variables["token"]}).scan(["/account/notes?q="])
    assert not [f for f in anon if f.url.endswith("/account/notes?q=")]
    assert [f for f in authed if f.rule == "REFLECTED-XSS" and f.url.endswith("/account/notes?q=")]


@pytest.mark.parametrize("name,expected_header", [("context-form.yaml", "Cookie"), ("context-header.yaml", "Authorization")])
def test_context_login_form_and_header(name, expected_header):
    with app.running(False) as srv:
        ctx = zest.load_context(HERE / "fixtures" / name, srv.base)
        headers = zest.login_with_context(ctx, ENV)
        assert list(headers) == [expected_header]
        assert zest.is_logged_in(ctx, headers)
        assert not zest.is_logged_in(ctx, {})


def test_context_password_comes_from_environment_not_file():
    text = (HERE / "fixtures" / "context-form.yaml").read_text()
    assert "${APP_PASSWORD}" in text and "demo-pass" not in text
    with app.running(False) as srv:
        ctx = zest.load_context(HERE / "fixtures" / "context-form.yaml", srv.base)
        with pytest.raises(KeyError):
            zest.login_with_context(ctx, {})


def test_wrong_password_fails_login():
    with app.running(False) as srv:
        ctx = zest.load_context(HERE / "fixtures" / "context-form.yaml", srv.base)
        with pytest.raises(zest.ZestError):
            zest.login_with_context(ctx, {"APP_PASSWORD": "nope-demo"})
