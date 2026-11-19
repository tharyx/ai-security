from aisec_lab import load_lab_module

w = load_lab_module(__file__, "weak_login")

USERS = {"carol": "p@ssw0rd"}  # weak lab password, last in the attack list


def test_dictionary_attack_cracks_weak_password_on_open_login():
    res = w.dictionary_attack(w.OpenLogin(USERS), "carol", w.ATTACK_WORDLIST)
    assert res["cracked"] is True
    assert res["password"] == "p@ssw0rd"
    assert res["tries"] == len(w.ATTACK_WORDLIST)


def test_lockout_stops_the_same_attack():
    login = w.GuardedLogin(USERS, max_failures=5, burst=100)
    res = w.dictionary_attack(login, "carol", w.ATTACK_WORDLIST)
    assert res["cracked"] is False and res["stopped_by"] == "locked"
    assert res["tries"] == 5
    # even the right password is refused while locked
    assert login.attempt("carol", "p@ssw0rd", now=1.0) == "locked"


def test_rate_limit_stops_a_fast_attacker_before_lockout():
    login = w.GuardedLogin(USERS, max_failures=100, rate_per_sec=1.0, burst=3)
    res = w.dictionary_attack(login, "carol", w.ATTACK_WORDLIST)
    assert res["cracked"] is False and res["stopped_by"] == "rate_limited"
    assert res["tries"] == 4  # 3 burst tokens, then refused


def test_rate_limit_bucket_refills_over_time():
    login = w.GuardedLogin(USERS, max_failures=100, rate_per_sec=1.0, burst=1)
    assert login.attempt("carol", "x", ip="2.2.2.2", now=0.0) == "fail"
    assert login.attempt("carol", "x", ip="2.2.2.2", now=0.1) == "rate_limited"
    assert login.attempt("carol", "p@ssw0rd", ip="2.2.2.2", now=2.0) == "ok"


def test_success_resets_failure_counter():
    login = w.GuardedLogin(USERS, max_failures=3, burst=100)
    login.attempt("carol", "a", now=0)
    login.attempt("carol", "b", now=0)
    assert login.attempt("carol", "p@ssw0rd", now=0) == "ok"
    assert "carol" not in login.failures
