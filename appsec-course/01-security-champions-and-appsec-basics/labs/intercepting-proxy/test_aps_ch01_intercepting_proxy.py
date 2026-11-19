import pytest

from aisec_lab import load_lab_module

mp = load_lab_module(__file__, "miniproxy")
ta = load_lab_module(__file__, "target_app")

CHECKOUT = ("POST /checkout HTTP/1.1\r\nHost: shop.example\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\nsku=7&price=499.00&qty=1")
ADMIN = "GET /admin HTTP/1.1\r\nHost: shop.example\r\nCookie: role=customer\r\n\r\n"
COUPON = "POST /coupon HTTP/1.1\r\nHost: shop.example\r\n\r\ncode=§X§"


def cheap(req):
    req.body = req.body.replace("price=499.00", "price=0.01")
    return req


def test_request_parse_and_serialize_round_trip():
    req = mp.parse_request(CHECKOUT)
    assert (req.method, req.target, req.version) == ("POST", "/checkout", "HTTP/1.1")
    assert req.header("host") == "shop.example" and req.body.endswith("qty=1")
    again = mp.parse_request(req.to_raw())
    assert again.body == req.body and again.header("Content-Length") == str(len(req.body))


def test_content_length_is_recomputed_after_tampering():
    req = mp.parse_request(CHECKOUT)
    req.body = "sku=7&price=0.01&qty=1"
    assert "Content-Length: 22" in req.to_raw()


def test_malformed_request_line_is_rejected():
    with pytest.raises(ValueError):
        mp.parse_request("GARBAGE\r\n\r\n")


def test_response_has_reason_phrase_and_status_class():
    resp = mp.parse_response(mp.HttpResponse(404, [("Content-Type", "text/plain")], "nope").to_raw())
    assert resp.status == 404 and resp.reason == "Not Found"
    assert mp.status_class(302) == "3xx Redirection" and mp.status_class(500) == "5xx Server error"


def test_price_tampering_works_on_vulnerable_checkout():
    app = ta.VulnerableCheckout()
    proxy = mp.InterceptingProxy(app)
    proxy.on_request(cheap)
    proxy.send(CHECKOUT)
    assert app.charges == [0.01]


def test_price_tampering_is_ignored_by_secure_checkout():
    app = ta.SecureCheckout()
    proxy = mp.InterceptingProxy(app)
    proxy.on_request(cheap)
    proxy.send(CHECKOUT)
    assert app.charges == [499.00]


def test_role_cookie_tamper_opens_admin_only_on_vulnerable():
    for cls, expected in ((ta.VulnerableCheckout, 200), (ta.SecureCheckout, 403)):
        proxy = mp.InterceptingProxy(cls())
        proxy.add_match_replace(r"role=customer", "role=admin")
        assert mp.parse_response(proxy.send(ADMIN)).status == expected


def test_history_and_repeater():
    proxy = mp.InterceptingProxy(ta.VulnerableCheckout())
    proxy.send("GET /product/7 HTTP/1.1\r\nHost: shop.example\r\n\r\n")
    resp = proxy.repeater(0, lambda q: setattr(q, "method", "DELETE"))
    assert len(proxy.history) == 2 and resp.status == 405
    assert proxy.history[0][0].method == "GET"  # original kept unchanged


def test_redirect_response_carries_location():
    proxy = mp.InterceptingProxy(ta.VulnerableCheckout())
    resp = mp.parse_response(proxy.send("GET /old-cart HTTP/1.1\r\nHost: shop.example\r\n\r\n"))
    assert resp.status == 302 and resp.header("Location") == "/product/7"


def test_intruder_finds_coupon_by_length_on_vulnerable():
    proxy = mp.InterceptingProxy(ta.VulnerableCheckout())
    rows = proxy.intruder_sniper(COUPON, ["A", "B", "WELCOME42", "C"])
    odd = [p for p, status, length in rows if length != rows[0][2]]
    assert odd == ["WELCOME42"]


def test_intruder_is_rate_limited_on_secure():
    proxy = mp.InterceptingProxy(ta.SecureCheckout())
    rows = proxy.intruder_sniper(COUPON, [f"G{i}" for i in range(5)] + ["WELCOME42"])
    assert rows[-1][1] == 429  # the right code arrives after the limit, so it is never confirmed


def test_intruder_template_needs_one_position():
    with pytest.raises(ValueError):
        mp.InterceptingProxy(ta.VulnerableCheckout()).intruder_sniper("GET / HTTP/1.1\r\n\r\n", ["x"])
