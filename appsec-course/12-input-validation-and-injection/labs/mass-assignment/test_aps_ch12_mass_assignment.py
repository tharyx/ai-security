import json

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "mass_assign")
ATTACK = json.dumps({"display_name": "A", "is_admin": True, "credit": 100000})


def test_attacker_becomes_admin_with_free_credit_on_vulnerable_api():
    s = m.Store()
    m.update_profile_vuln(s, 1, ATTACK)
    assert s.users[1].is_admin is True and s.users[1].credit == 100000


def test_secure_api_rejects_unknown_fields_and_changes_nothing():
    s = m.Store()
    status, body = m.update_profile_safe(s, 1, ATTACK)
    assert status == 422 and "is_admin" in body["error"]
    assert s.users[1].is_admin is False and s.users[1].credit == 0


def test_secure_api_accepts_allowlisted_fields_and_hides_internal_ones():
    s = m.Store()
    status, body = m.update_profile_safe(s, 1, json.dumps({"display_name": "Alice K"}))
    assert status == 200 and body["display_name"] == "Alice K" and "is_admin" not in body


def test_secure_api_validates_types_and_lengths():
    s = m.Store()
    assert m.update_profile_safe(s, 1, json.dumps({"display_name": ""}))[0] == 422
    assert m.update_profile_safe(s, 1, json.dumps({"display_name": ["x"]}))[0] == 422


def test_email_change_resets_verification_server_side():
    s = m.Store()
    s.users[1].email_verified = True
    m.update_profile_safe(s, 1, json.dumps({"email": "new@lab.example"}))
    assert s.users[1].email_verified is False
