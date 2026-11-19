import json
from pathlib import Path

from aisec_lab import load_lab_module

hd = load_lab_module(__file__, "headers")
FX = Path(__file__).resolve().parent / "fixtures"


def load(name):
    return json.loads((FX / name).read_text())


def test_legacy_response_flags_the_classic_problems():
    got = hd.ids(hd.analyze(load("legacy_api_response.json"), request_origin="https://evil.attacker.test"))
    assert {"XXP-01", "HSTS-01", "CACHE-01", "FRAME-03", "CSP-02", "CSP-05", "CORS-03",
            "COOKIE-01", "COOKIE-02", "NOSNIFF-01", "INFO-01"} <= got


def test_hardened_response_has_no_findings():
    assert hd.analyze(load("hardened_api_response.json"), request_origin="https://shop.example") == []


def test_x_xss_protection_zero_is_fine_but_enabling_it_is_flagged():
    assert "XXP-01" not in hd.ids(hd.analyze({"X-XSS-Protection": "0"}))
    assert "XXP-01" in hd.ids(hd.analyze({"X-XSS-Protection": "1; mode=block"}))


def test_xfo_only_is_told_to_move_to_frame_ancestors():
    got = hd.ids(hd.analyze({"X-Frame-Options": "DENY"}))
    assert "FRAME-02" in got and "FRAME-01" not in got


def test_short_hsts_is_flagged():
    got = hd.ids(hd.analyze({"Strict-Transport-Security": "max-age=3600"}))
    assert {"HSTS-02", "HSTS-03"} <= got


def test_csp_evaluator_common_misconfigurations():
    assert "CSP-04" in hd.ids(hd.evaluate_csp("script-src https: 'self'"))
    assert "CSP-03" in hd.ids(hd.evaluate_csp("script-src 'self' 'unsafe-eval'"))
    # a nonce makes CSP2+ browsers ignore 'unsafe-inline' (backward-compat pattern)
    assert "CSP-02" not in hd.ids(hd.evaluate_csp("script-src 'nonce-x' 'unsafe-inline' 'strict-dynamic'"))
    strict = hd.evaluate_csp(hd.build_strict_csp("abc"))
    assert strict == []


def test_report_only_csp_blocks_nothing():
    got = hd.ids(hd.analyze({"Content-Security-Policy-Report-Only": hd.build_strict_csp("n")}))
    assert "CSP-10" in got


def test_unanchored_cors_regex_and_reflection_allow_attacker_origins():
    evil = "https://shop.example.attacker.test"
    assert hd.cors_vulnerable_regex(evil) and hd.cors_vulnerable_reflect(evil)
    assert not hd.cors_secure(evil) and not hd.cors_secure("null")
    assert hd.cors_secure("https://shop.example")
    assert "Access-Control-Allow-Origin" not in hd.cors_response(evil, hd.cors_secure(evil))


def test_samesite_controls_cross_site_cookie_sending():
    assert not hd.cookie_sent("Strict", True, "cross-site-top-level-get")
    assert hd.cookie_sent("Lax", True, "cross-site-top-level-get")
    assert not hd.cookie_sent("Lax", True, "cross-site-post")  # classic CSRF form post blocked
    assert hd.cookie_sent("None", True, "cross-site-post")     # needs a CSRF token
    assert not hd.cookie_sent("None", False, "same-site")


def test_host_prefix_rules_are_enforced():
    assert "COOKIE-05" in hd.ids(hd.check_cookie("__Host-s=1; Secure; HttpOnly; SameSite=Lax; Domain=shop.example; Path=/"))
    assert hd.check_cookie("__Host-s=1; Secure; HttpOnly; SameSite=Strict; Path=/") == []
