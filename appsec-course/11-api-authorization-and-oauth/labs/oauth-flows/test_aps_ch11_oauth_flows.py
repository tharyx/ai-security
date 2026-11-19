import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from aisec_lab import load_lab_module

o = load_lab_module(__file__, "oauth_sim")
CB = "https://app.lab.example"
FIX = Path(__file__).resolve().parent / "fixtures"


def _as(secure):
    a = o.AuthServer(secure=secure)
    a.register(o.Client("spa", [CB]))
    return a


def _code(a, challenge=None, state="st", scope="openid trips:read"):
    p = {"client_id": "spa", "redirect_uri": CB, "response_type": "code", "state": state, "scope": scope, "nonce": "n1"}
    if challenge:
        p.update(code_challenge=challenge, code_challenge_method="S256")
    return parse_qs(urlparse(a.authorize("alice", p)).query)["code"][0]


def test_pkce_happy_path_returns_access_refresh_and_id_tokens():
    a = _as(True)
    v, ch = o.pkce_pair()
    t = a.token({"grant_type": "authorization_code", "code": _code(a, ch), "client_id": "spa",
                 "redirect_uri": CB, "code_verifier": v})
    assert {"access_token", "refresh_token", "id_token"} <= set(t)
    assert o.api_accepts(t["access_token"], a.key, True, "trips:read")


def test_stolen_code_redeemed_without_verifier_only_on_vulnerable_as():
    v_as, s_as = _as(False), _as(True)
    _, ch = o.pkce_pair()
    assert "access_token" in v_as.token({"grant_type": "authorization_code", "code": _code(v_as, ch),
                                         "client_id": "spa", "redirect_uri": CB})
    with pytest.raises(ValueError, match="PKCE"):
        s_as.token({"grant_type": "authorization_code", "code": _code(s_as, ch), "client_id": "spa", "redirect_uri": CB})


def test_secure_as_requires_pkce_s256_at_authorize():
    with pytest.raises(ValueError, match="PKCE"):
        _code(_as(True))


def test_redirect_uri_prefix_trick_sends_code_to_attacker_only_on_vulnerable_as():
    evil = CB + ".evil.example/x"
    url = _as(False).authorize("alice", {"client_id": "spa", "redirect_uri": evil, "response_type": "code"})
    assert urlparse(url).hostname == "app.lab.example.evil.example"  # attacker-controlled host
    with pytest.raises(ValueError):
        _as(True).authorize("alice", {"client_id": "spa", "redirect_uri": evil, "response_type": "code"})


def test_code_reuse_allowed_on_vulnerable_but_single_use_on_secure():
    v_as = _as(False)
    c = _code(v_as)
    req = {"grant_type": "authorization_code", "code": c, "client_id": "spa", "redirect_uri": CB}
    v_as.token(req)
    assert "access_token" in v_as.token(req)
    s_as = _as(True)
    v, ch = o.pkce_pair()
    req = {"grant_type": "authorization_code", "code": _code(s_as, ch), "client_id": "spa", "redirect_uri": CB,
           "code_verifier": v}
    s_as.token(req)
    with pytest.raises(ValueError, match="already used"):
        s_as.token(req)


def test_implicit_and_password_grants_removed_on_secure_as():
    assert "#access_token=" in _as(False).authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "token"})
    with pytest.raises(ValueError, match="implicit"):
        _as(True).authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "token"})
    with pytest.raises(ValueError):
        _as(True).token({"grant_type": "password", "username": "alice", "client_id": "spa"})


def test_missing_state_check_allows_login_csrf_and_check_blocks_it():
    a = _as(False)
    attacker_url = a.authorize("mallory", {"client_id": "spa", "redirect_uri": CB, "response_type": "code"})
    assert o.client_callback(attacker_url, None)  # client that skips state accepts attacker's code
    with pytest.raises(ValueError, match="state mismatch"):
        o.client_callback(attacker_url, "victims-state")


def test_id_token_is_accepted_by_naive_api_but_rejected_by_secure_api():
    a = _as(True)
    v, ch = o.pkce_pair()
    t = a.token({"grant_type": "authorization_code", "code": _code(a, ch), "client_id": "spa",
                 "redirect_uri": CB, "code_verifier": v})
    assert o.api_accepts(t["id_token"], a.key, secure=False)
    assert not o.api_accepts(t["id_token"], a.key, secure=True)
    assert not o.api_accepts(t["access_token"], a.key, True, "payouts:read")  # scope enforced


def test_refresh_reuse_detection_revokes_whole_family():
    a = _as(True)
    v, ch = o.pkce_pair()
    t = a.token({"grant_type": "authorization_code", "code": _code(a, ch), "client_id": "spa",
                 "redirect_uri": CB, "code_verifier": v})
    new = a.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
    with pytest.raises(ValueError, match="reuse"):
        a.token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
    with pytest.raises(ValueError):
        a.token({"grant_type": "refresh_token", "refresh_token": new["refresh_token"]})


def test_config_audit_flags_insecure_client_and_passes_secure_one():
    bad = o.audit_client_config(json.loads((FIX / "client_insecure.json").read_text()))
    good = o.audit_client_config(json.loads((FIX / "client_secure.json").read_text()))
    assert len(bad) >= 8 and any("implicit" in x for x in bad) and any("PKCE" in x for x in bad)
    assert good == []
