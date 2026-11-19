from aisec_lab import load_lab_module

r = load_lab_module(__file__, "reset")
USERS = {"alice": "old-password-value"}
NOW = 1_700_000_000


def test_attacker_predicts_vulnerable_token_and_takes_over():
    svc = r.VulnerableReset(USERS)
    svc.request("alice", "shop.lab.example", NOW)
    guessed = r.VulnerableReset.make_token("alice", NOW)  # attacker computes it
    assert svc.confirm(guessed, "attacker-pw", NOW + 5)
    assert svc.users["alice"] == "attacker-pw"


def test_vulnerable_token_is_reusable_and_never_expires():
    svc = r.VulnerableReset(USERS)
    svc.request("alice", "shop.lab.example", NOW)
    tok = r.token_from_link(svc.outbox[-1][1])
    assert svc.confirm(tok, "first", NOW + 10)
    assert svc.confirm(tok, "second", NOW + 10 * 86400)  # 10 days later, again


def test_host_header_poisoning_sends_link_to_attacker_domain():
    svc = r.VulnerableReset(USERS)
    svc.request("alice", "evil.attacker.example", NOW)
    assert svc.outbox[-1][1].startswith("https://evil.attacker.example/")
    sec = r.SecureReset(USERS)
    sec.request("alice", "evil.attacker.example", NOW)
    assert sec.outbox[-1][1].startswith(r.SecureReset.BASE_URL)


def test_vulnerable_reset_enumerates_users_secure_does_not():
    v, s = r.VulnerableReset(USERS), r.SecureReset(USERS)
    assert v.request("alice", "h", NOW) != v.request("ghost", "h", NOW)
    assert s.request("alice", "h", NOW) == s.request("ghost", "h", NOW)


def test_secure_token_is_single_use_and_stored_hashed():
    s = r.SecureReset(USERS)
    s.request("alice", "h", NOW)
    tok = r.token_from_link(s.outbox[-1][1])
    assert tok not in str(s.tokens)  # only the hash is stored
    assert s.confirm(tok, "a-new-long-passphrase", NOW + 60)
    assert not s.confirm(tok, "another-long-passphrase", NOW + 61)


def test_secure_token_expires():
    s = r.SecureReset(USERS)
    s.request("alice", "h", NOW)
    tok = r.token_from_link(s.outbox[-1][1])
    assert not s.confirm(tok, "a-new-long-passphrase", NOW + r.SecureReset.TTL + 1)


def test_secure_reset_rejects_short_new_password_and_guessing():
    s = r.SecureReset(USERS)
    s.request("alice", "h", NOW)
    assert not s.confirm(r.VulnerableReset.make_token("alice", NOW), "a-new-long-passphrase", NOW)
    tok = r.token_from_link(s.outbox[-1][1])
    assert not s.confirm(tok, "short", NOW + 1)
