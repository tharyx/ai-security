import pytest

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "cors_lab")
ATTACKERS = ["https://evil.example", "null", "https://evilbank.example", "https://bank.example.evil.net"]


@pytest.mark.parametrize("policy,origin", [
    ("reflect", "https://evil.example"),
    ("null", "null"),
    ("suffix", "https://evilbank.example"),
    ("prefix", "https://bank.example.evil.net"),
])
def test_misconfigured_policy_lets_attacker_page_read_credentialed_response(policy, origin):
    assert c.browser_cross_origin_read(origin, policy)["api_key"] == "FAKE-key-0000"


@pytest.mark.parametrize("origin", ATTACKERS)
def test_exact_allowlist_blocks_every_attacker_origin(origin):
    assert c.browser_cross_origin_read(origin, "secure") is None


def test_wildcard_cannot_be_combined_with_credentials_by_browsers():
    assert c.browser_cross_origin_read("https://evil.example", "wildcard", with_credentials=True) is None
    assert c.browser_cross_origin_read("https://evil.example", "wildcard", with_credentials=False) == {"error": "login"}


def test_allowed_origin_reads_and_vary_origin_is_set():
    assert c.browser_cross_origin_read("https://app.bank.example", "secure")["user"] == "alice"
    assert c.cors_headers("https://evil.example", "secure") == {"Vary": "Origin"}


def test_cors_is_not_csrf_protection():
    assert c.simple_post_reaches_server("application/x-www-form-urlencoded")
    assert not c.simple_post_reaches_server("application/json")  # needs a preflight
