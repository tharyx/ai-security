import json
from pathlib import Path

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "minigw")
CFG = Path(__file__).resolve().parent / "fixtures" / "kong-like.json"


def setup():
    keys = {"mobile-app": g.new_fake_api_key(), "partner-acme": g.new_fake_api_key()}
    api = g.UpstreamAPI(pin="0019")
    gw = g.Gateway(g.load_config(CFG, keys), {"orders-api": api})
    return gw, api, keys


def guess(target, n):
    return target("POST", "/login", {}, json.dumps({"pin": f"{n:04d}"}))[0]


def test_pin_brute_force_succeeds_directly_against_upstream():
    api = g.UpstreamAPI(pin="0019")
    assert 200 in [guess(api, n) for n in range(30)]


def test_gateway_rate_limit_stops_the_brute_force_before_the_right_pin():
    gw, api, _ = setup()
    statuses = [guess(lambda m, p, h, b: gw.handle(m, p, h, b), n) for n in range(30)]
    assert 200 not in statuses and statuses.count(429) == 25
    assert api.calls == 5  # blocked requests never reach the upstream


def test_429_carries_retry_after_and_bucket_refills():
    gw, _, _ = setup()
    for n in range(5):
        gw.handle("POST", "/login", {}, '{"pin":"1"}')
    status, h, _ = gw.handle("POST", "/login", {}, '{"pin":"1"}')
    assert status == 429 and int(h["Retry-After"]) >= 1
    gw.clock.advance(13)
    assert gw.handle("POST", "/login", {}, '{"pin":"1"}')[0] == 401  # reached upstream again


def test_ip_based_limit_is_per_client_ip():
    gw, _, _ = setup()
    for _ in range(6):
        gw.handle("POST", "/login", {}, "{}", client_ip="203.0.113.1")
    assert gw.handle("POST", "/login", {}, "{}", client_ip="203.0.113.1")[0] == 429
    assert gw.handle("POST", "/login", {}, "{}", client_ip="203.0.113.2")[0] == 401


def test_missing_or_unknown_api_key_is_rejected_at_the_gateway():
    gw, api, _ = setup()
    assert gw.handle("GET", "/orders")[0] == 401
    assert gw.handle("GET", "/orders", {"apikey": g.new_fake_api_key()})[0] == 401
    assert api.calls == 0


def test_per_api_key_limits_are_independent():
    gw, _, keys = setup()
    a = [gw.handle("GET", "/orders", {"apikey": keys["mobile-app"]})[0] for _ in range(12)]
    assert a.count(200) == 10 and a.count(429) == 2
    assert gw.handle("GET", "/orders", {"apikey": keys["partner-acme"]})[0] == 200


def test_consumer_identity_is_set_by_gateway_not_client():
    gw, _, keys = setup()
    _, _, body = gw.handle("GET", "/orders", {"apikey": keys["partner-acme"], "X-Consumer-Username": "mobile-app"})
    assert json.loads(body)["for"] == "partner-acme"


def test_security_headers_added_and_leaky_headers_removed():
    gw, _, keys = setup()
    _, h, _ = gw.handle("GET", "/orders", {"apikey": keys["partner-acme"]})
    assert h["Cache-Control"] == "no-store" and h["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in h["Strict-Transport-Security"] and h["X-XSS-Protection"] == "0"
    assert "Server" not in h and "X-Powered-By" not in h


def test_headers_also_present_on_gateway_errors():
    gw, _, _ = setup()
    _, h, _ = gw.handle("GET", "/orders")
    assert h["Cache-Control"] == "no-store"


def test_cors_only_for_allowlisted_origin():
    gw, _, keys = setup()
    _, ok, _ = gw.handle("GET", "/orders", {"apikey": keys["partner-acme"], "Origin": "https://shop.example"})
    _, bad, _ = gw.handle("GET", "/orders", {"apikey": keys["partner-acme"], "Origin": "https://evil.attacker.test"})
    assert ok["Access-Control-Allow-Origin"] == "https://shop.example"
    assert "Access-Control-Allow-Origin" not in bad
