from aisec_lab import load_lab_module

u = load_lab_module(__file__, "userenum")

USERS = {"alice": "pw-alice", "bob": "pw-bob"}
CANDIDATES = ["alice", "carol", "bob", "dave"]


def test_vulnerable_login_leaks_existence_via_status_and_message():
    auth = u.VulnerableAuth(USERS)
    present = auth.login("alice", "wrong")
    absent = auth.login("carol", "wrong")
    assert present.status == 401 and absent.status == 404
    assert present.message != absent.message
    assert present.work_units > absent.work_units  # timing side channel


def test_enumeration_recovers_real_users_on_vulnerable_api():
    auth = u.VulnerableAuth(USERS)
    found = set(u.enumerate_users(auth, CANDIDATES))
    assert found == {"alice", "bob"}


def test_secure_login_is_uniform_so_enumeration_fails():
    auth = u.SecureAuth(USERS)
    present = auth.login("alice", "wrong")
    absent = auth.login("carol", "wrong")
    assert present.status == absent.status == 401
    assert present.message == absent.message == u.SecureAuth.GENERIC
    assert present.work_units == absent.work_units
    assert u.enumerate_users(auth, CANDIDATES) == []


def test_secure_login_still_lets_the_right_password_in():
    auth = u.SecureAuth(USERS)
    assert auth.login("alice", "pw-alice").status == 200


def test_vulnerable_register_and_reset_also_leak():
    auth = u.VulnerableAuth(USERS)
    assert auth.register("alice").status == 409   # taken -> exists
    assert auth.register("new").status == 201
    assert auth.reset("bob").message != auth.reset("ghost").message


def test_secure_register_and_reset_do_not_leak():
    auth = u.SecureAuth(USERS)
    assert auth.register("alice").status == auth.register("new").status
    assert auth.reset("bob").message == auth.reset("ghost").message
