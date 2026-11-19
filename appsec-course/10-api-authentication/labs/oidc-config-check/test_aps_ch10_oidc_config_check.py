from pathlib import Path

from aisec_lab import load_lab_module

o = load_lab_module(__file__, "oidccheck")
FX = Path(__file__).resolve().parent / "fixtures"
ISS = "https://login.lab.example"


def _rules(name):
    return {f.rule for f in o.check_discovery(o.load(FX / name), ISS)}


def test_insecure_discovery_flags_the_big_problems():
    rules = _rules("discovery_insecure.json")
    for r in ["OIDC-ISSUER-MISMATCH", "OIDC-NO-TLS", "OIDC-ALG-NONE", "OIDC-IMPLICIT",
              "OAUTH-IMPLICIT-GRANT", "OAUTH-ROPC-GRANT", "OAUTH-PKCE-PLAIN", "OIDC-JWKS-OFFSITE"]:
        assert r in rules, r


def test_insecure_discovery_fails_the_gate():
    assert o.gate(o.check_discovery(o.load(FX / "discovery_insecure.json"), ISS)) == 1


def test_secure_discovery_is_clean():
    findings = o.check_discovery(o.load(FX / "discovery_secure.json"), ISS)
    assert findings == []
    assert o.gate(findings) == 0


def test_missing_pkce_is_flagged():
    doc = o.load(FX / "discovery_secure.json")
    del doc["code_challenge_methods_supported"]
    assert "OAUTH-NO-PKCE" in {f.rule for f in o.check_discovery(doc, ISS)}


GOOD = {"iss": ISS, "aud": "shop-spa", "exp": 2000, "nonce": "n-123", "sub": "alice"}


def test_valid_id_token_claims_pass():
    assert o.validate_id_token_claims(GOOD, issuer=ISS, client_id="shop-spa",
                                      nonce="n-123", now=1000) == []


def test_id_token_for_another_client_is_rejected():
    bad = dict(GOOD, aud="other-app")
    assert "aud does not contain our client_id" in o.validate_id_token_claims(
        bad, issuer=ISS, client_id="shop-spa", nonce="n-123", now=1000)


def test_replayed_or_expired_id_token_is_rejected():
    probs = o.validate_id_token_claims(dict(GOOD, nonce="old", exp=500), issuer=ISS,
                                       client_id="shop-spa", nonce="n-123", now=1000)
    assert "nonce mismatch (possible replay)" in probs
    assert "expired or missing exp" in probs
