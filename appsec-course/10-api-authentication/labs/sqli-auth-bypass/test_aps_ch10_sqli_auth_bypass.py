from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sqli_login")


def test_legitimate_login_works_on_both():
    con = s.make_db()
    assert s.login_vulnerable(con, "alice", "pw-alice")["role"] == "user"
    assert s.login_secure(con, "alice", "pw-alice")["role"] == "user"


def test_wrong_password_fails_on_both():
    con = s.make_db()
    assert s.login_vulnerable(con, "alice", "nope") is None
    assert s.login_secure(con, "alice", "nope") is None


def test_injection_bypasses_vulnerable_login_without_a_password():
    con = s.make_db()
    result = s.login_vulnerable(con, s.BYPASS_USERNAME, "any-wrong-password")
    assert result is not None  # logged in with no valid credentials


def test_injection_can_target_admin_on_vulnerable_login():
    con = s.make_db()
    result = s.login_vulnerable(con, s.BYPASS_ADMIN, "irrelevant")
    assert result is not None and result["role"] == "admin"


def test_secure_login_treats_injection_as_data():
    con = s.make_db()
    assert s.login_secure(con, s.BYPASS_USERNAME, "any") is None
    assert s.login_secure(con, s.BYPASS_ADMIN, "any") is None


def test_passwords_are_not_stored_in_plaintext():
    con = s.make_db()
    stored = con.execute("SELECT pw_hash FROM users WHERE username='alice'").fetchone()[0]
    assert stored != "pw-alice" and len(stored) == 64
