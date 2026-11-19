from aisec_lab import load_lab_module

j = load_lab_module(__file__, "jwt_privesc")


def test_hs256_helper_round_trip_and_tamper_detection():
    api = j.VulnerableAPI()
    t = api.issue("u-alice")
    assert api.verify(t) == {"sub": "u-alice", "role": "user"}
    h, _, s = t.split(".")
    evil_payload = j.b64url(b'{"sub":"u-alice","role":"admin"}')
    tampered = f"{h}.{evil_payload}.{s}"
    assert api.verify(tampered) is None  # editing the payload breaks the signature


def test_normal_user_is_denied_payouts_on_both_apis():
    for api in (j.VulnerableAPI(), j.SecureAPI()):
        assert api.get_payouts(api.issue("u-alice"))[0] == 403


def test_alg_none_role_admin_grants_payouts_on_vulnerable_api():
    api = j.VulnerableAPI()
    forged = j.forge_alg_none(api.issue("u-alice"), role="admin")
    assert forged.endswith(".")  # no signature at all
    assert api.get_payouts(forged)[0] == 200


def test_weak_secret_is_cracked_and_forged_admin_token_works_on_vulnerable_api():
    api = j.VulnerableAPI()
    tok = api.issue("u-alice")
    key = j.crack_hs256(tok, j.WORDLIST)
    assert key == api.key
    assert api.get_payouts(j.forge_with_key(tok, key, role="admin"))[0] == 200


def test_secure_api_rejects_alg_none_and_cannot_be_cracked():
    api = j.SecureAPI()
    tok = api.issue("u-alice")
    assert api.get_payouts(j.forge_alg_none(tok, role="admin"))[0] == 401
    assert j.crack_hs256(tok, j.WORDLIST) is None


def test_secure_api_ignores_role_claim_even_if_correctly_signed():
    api = j.SecureAPI()
    tok = j.forge_with_key(api.issue("u-alice"), api.key, role="admin")  # insider with the key
    assert api.get_payouts(tok)[0] == 403  # role comes from server-side data


def test_secure_api_checks_exp_iss_and_aud():
    clock = [1_000_000]
    api = j.SecureAPI(now=lambda: clock[0])
    tok = api.issue("u-carol", ttl=60)
    assert api.get_payouts(tok)[0] == 200
    assert api.get_payouts(j.forge_with_key(tok, api.key, aud="other-api"))[0] == 401
    assert api.get_payouts(j.forge_with_key(tok, api.key, iss="https://evil.example"))[0] == 401
    clock[0] += 61
    assert api.get_payouts(tok)[0] == 401


def test_vulnerable_api_accepts_token_with_no_expiry_forever():
    api = j.VulnerableAPI()
    assert "exp" not in j.decode_unverified(api.issue("u-alice"))[1]
