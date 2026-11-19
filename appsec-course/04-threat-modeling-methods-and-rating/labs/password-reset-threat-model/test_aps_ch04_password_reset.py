from aisec_lab import load_lab_module

A = load_lab_module(__file__, "attacks")
V = load_lab_module(__file__, "reset_vulnerable").ResetService
S = load_lab_module(__file__, "reset_secure").ResetService
R = load_lab_module(__file__, "requirements")


def fresh(cls):
    clock = A.Clock()
    return cls(clock=clock), clock


def test_predictable_token_lets_attacker_take_over_account_only_on_vulnerable():
    svc, clock = fresh(V)
    assert A.predict_token(svc, clock) is True and svc.check_password(A.VICTIM, A.NEW_PW)
    svc, clock = fresh(S)
    assert A.predict_token(svc, clock) is False and not svc.check_password(A.VICTIM, A.NEW_PW)


def test_user_enumeration_works_on_vulnerable_only():
    assert A.enumerate_users(fresh(V)[0], ["alice@example.com", "carol@example.com"]) == {"alice@example.com"}
    assert A.enumerate_users(fresh(S)[0], ["alice@example.com", "carol@example.com"]) == set()


def test_host_header_poisoning_redirects_link_on_vulnerable_only():
    assert A.host_header_poisoning(fresh(V)[0]) is True
    svc = fresh(S)[0]
    assert A.host_header_poisoning(svc) is False and svc.outbox[-1][1].startswith("https://shop.example/")


def test_tokens_are_single_use_and_expire_on_secure():
    assert A.replay_token(fresh(V)[0]) and not A.replay_token(fresh(S)[0])
    v, vc = fresh(V)
    s, sc = fresh(S)
    assert A.use_expired_token(v, vc) and not A.use_expired_token(s, sc)


def test_db_dump_and_logs_leak_tokens_on_vulnerable_only():
    assert A.token_from_db_dump(fresh(V)[0]) and not A.token_from_db_dump(fresh(S)[0])
    assert A.token_in_logs(fresh(V)[0]) and not A.token_in_logs(fresh(S)[0])


def test_sessions_revoked_and_password_policy_enforced_on_secure():
    assert A.session_survives_reset(fresh(V)[0]) and not A.session_survives_reset(fresh(S)[0])
    assert A.weak_password_accepted(fresh(V)[0]) and not A.weak_password_accepted(fresh(S)[0])


def test_rate_limit_and_audit_trail():
    assert A.mailbox_flood(fresh(V)[0]) and not A.mailbox_flood(fresh(S)[0])
    assert A.no_audit_record(fresh(V)[0]) and not A.no_audit_record(fresh(S)[0])


def test_secure_service_still_works_for_the_real_user():
    svc, _ = fresh(S)
    status, msg = svc.request_reset(A.VICTIM)
    assert status == 202 and "If an account exists" in msg
    token = svc.outbox[-1][1].split("token=")[1]
    assert len(token) >= 43  # 32 random bytes, base64url
    assert svc.reset(token, "victim-new-passphrase-2026")[0] == 200
    assert svc.check_password(A.VICTIM, "victim-new-passphrase-2026")


def test_every_requirement_fails_on_vulnerable_and_passes_on_secure():
    assert R.verify(V) == {r.id: False for r in R.REQUIREMENTS}
    assert R.verify(S) == {r.id: True for r in R.REQUIREMENTS}


def test_requirements_cover_all_six_stride_categories():
    assert {r.stride for r in R.REQUIREMENTS} == set("STRIDE")
    assert all(r.text and r.threat for r in R.REQUIREMENTS)
