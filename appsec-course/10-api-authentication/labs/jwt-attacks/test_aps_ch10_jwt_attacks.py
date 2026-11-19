import time

from aisec_lab import load_lab_module

j = load_lab_module(__file__, "jwtlab")

STRONG_SECRET = "FAKE-" + "9f3c2a7b61e04d58" + "-DEMO"  # built at runtime, labelled FAKE
AUD = "shop-api"


def _token(exp_offset=3600, **extra):
    payload = {"sub": "alice", "aud": AUD, "exp": int(time.time()) + exp_offset}
    payload.update(extra)
    return j.encode_hs256(payload, STRONG_SECRET)


def test_round_trip_encode_then_strict_verify():
    tok = _token(role="user")
    claims = j.verify_strict(tok, STRONG_SECRET, audience=AUD)
    assert claims["sub"] == "alice" and claims["role"] == "user"


def test_alg_none_bypasses_naive_but_not_strict():
    forged = j.forge_alg_none({"sub": "attacker", "role": "admin", "aud": AUD,
                               "exp": int(time.time()) + 3600})
    # naive verifier trusts alg:none
    assert j.verify_naive(forged, STRONG_SECRET)["role"] == "admin"
    # strict verifier refuses any alg that is not HS256
    try:
        j.verify_strict(forged, STRONG_SECRET, audience=AUD)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_weak_secret_is_cracked_from_tiny_wordlist():
    weak = j.make_fake_weak_secret()
    assert weak in j.TINY_WORDLIST
    tok = j.encode_hs256({"sub": "bob", "aud": AUD, "exp": int(time.time()) + 60}, weak)
    cracked = j.crack_hs256_secret(tok, j.TINY_WORDLIST)
    assert cracked == weak
    # once cracked, an attacker forges a valid admin token
    forged = j.encode_hs256({"sub": "bob", "role": "admin", "aud": AUD,
                             "exp": int(time.time()) + 60}, cracked)
    assert j.verify_strict(forged, cracked, audience=AUD)["role"] == "admin"


def test_strong_secret_is_not_in_the_wordlist():
    tok = _token()
    assert j.crack_hs256_secret(tok, j.TINY_WORDLIST) is None


def test_missing_exp_is_rejected_by_strict():
    tok = j.encode_hs256({"sub": "alice", "aud": AUD}, STRONG_SECRET)  # no exp
    # naive accepts it
    assert j.verify_naive(tok, STRONG_SECRET)["sub"] == "alice"
    try:
        j.verify_strict(tok, STRONG_SECRET, audience=AUD)
        raised = False
    except ValueError as e:
        raised = "exp" in str(e)
    assert raised


def test_expired_token_is_rejected():
    tok = _token(exp_offset=-10)  # already expired
    try:
        j.verify_strict(tok, STRONG_SECRET, audience=AUD)
        raised = False
    except ValueError as e:
        raised = "expired" in str(e)
    assert raised


def test_wrong_audience_is_rejected():
    tok = _token()
    try:
        j.verify_strict(tok, STRONG_SECRET, audience="other-api")
        raised = False
    except ValueError as e:
        raised = "audience" in str(e)
    assert raised


def test_kid_path_traversal_picks_attacker_known_key():
    # The vulnerable resolver uses kid as a path; a traversal kid reaches a
    # world-readable file whose contents the attacker knows ("public").
    key_dir = {"main": STRONG_SECRET, "../../public/keys/pub": "public"}
    good = j.resolve_key_vulnerable("main", key_dir)
    traversed = j.resolve_key_vulnerable("../../public/keys/pub", key_dir)
    assert good == STRONG_SECRET
    assert traversed == "public"
    # the safe resolver refuses anything with a slash or traversal
    try:
        j.resolve_key_safe("../../public/keys/pub", key_dir)
        raised = False
    except ValueError:
        raised = True
    assert raised
    assert j.resolve_key_safe("main", key_dir) == STRONG_SECRET
