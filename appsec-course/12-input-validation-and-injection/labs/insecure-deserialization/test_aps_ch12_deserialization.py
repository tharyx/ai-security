import pickle

import pytest

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "deser")


def setup_function():
    d.CANARY.clear()


def test_unpickling_attacker_cookie_runs_attacker_chosen_function():
    session = d.load_session_vuln(d.make_malicious_cookie())
    assert session["prefs"] == "session-hijacked"
    assert len(d.CANARY) == 1 and d.CANARY[0].startswith("RCE-CANARY")


def test_json_schema_loader_cannot_execute_code_and_rejects_pickle():
    with pytest.raises(Exception):
        d.load_session_json(d.make_malicious_cookie())
    assert d.CANARY == []


def test_json_schema_loader_rejects_unexpected_shapes():
    with pytest.raises(ValueError):
        d.load_session_json(d.dump_session_json({"user": "a", "prefs": {"theme": "x"}, "is_admin": True}))
    assert d.load_session_json(d.dump_session_json({"user": "a", "prefs": {"lang": "en"}}))["user"] == "a"


def test_restricted_unpickler_blocks_global_lookup_before_any_call():
    with pytest.raises(pickle.UnpicklingError, match="forbidden"):
        d.load_session_restricted(d.make_malicious_cookie())
    assert d.CANARY == []


def test_restricted_unpickler_still_loads_plain_data():
    assert d.load_session_restricted(d.make_normal_cookie("bob"))["user"] == "bob"


def test_hmac_signature_rejects_tampered_cookie():
    signed = d.sign(d.make_normal_cookie())
    assert d.verify_and_split(signed)
    with pytest.raises(ValueError):
        d.verify_and_split(d.make_malicious_cookie() + "." + signed.rpartition(".")[2])
