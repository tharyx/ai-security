from __future__ import annotations

import base64
import json

import pytest

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "acp_session")


def forge_vuln(blob_b64: str, **changes) -> str:
    d = json.loads(base64.b64decode(blob_b64))
    d.update(changes)
    return base64.b64encode(json.dumps(d).encode()).decode()


def test_vulnerable_fixation_gives_attacker_the_admin_session():
    v = m.VulnerableSessions()
    v.precreate("sess-attacker")
    v.login("admin-agent", "FAKE-s2", "sess-attacker")
    assert v.call("sess-attacker", "wire_funds").endswith("admin-agent")


def test_vulnerable_ids_are_predictable():
    v = m.VulnerableSessions()
    assert v.login("report-agent", "FAKE-s1") == "sess-1"
    assert v.login("admin-agent", "FAKE-s2") == "sess-2"  # attacker can guess the next one


def test_vulnerable_state_tampering_escalates_reader_to_admin():
    v = m.VulnerableSessions()
    low = v.login("report-agent", "FAKE-s1")
    with pytest.raises(m.AccessDenied):
        v.call(low, "wire_funds")
    forged = v.resume(forge_vuln(v.export_state(low), role="admin"))
    assert "wire_funds ok" in v.call(forged, "wire_funds")


def test_secure_fixation_fails_and_ids_are_random():
    s = m.SecureSessions()
    s.precreate("sess-attacker")
    sid = s.login("admin-agent", "FAKE-s2", "sess-attacker")
    assert sid != "sess-attacker" and len(sid) == 32
    with pytest.raises(m.AccessDenied):
        s.call("sess-attacker", "wire_funds")
    assert s.login("admin-agent", "FAKE-s2") != sid  # rotates on every login


def test_secure_tampered_token_is_refused():
    s = m.SecureSessions()
    low = s.login("report-agent", "FAKE-s1")
    tok = s.export_state(low)
    b64, sig = tok.rsplit(".", 1)
    body = json.loads(base64.b64decode(b64))
    body["agent"] = "admin-agent"
    forged = base64.b64encode(json.dumps(body, sort_keys=True).encode()).decode() + "." + sig
    with pytest.raises(m.AccessDenied, match="signature"):
        s.resume(forged, "report-agent")
    with pytest.raises(m.AccessDenied):
        s.resume("not-a-token", "report-agent")


def test_secure_role_is_never_taken_from_the_client():
    s = m.SecureSessions()
    low = s.login("report-agent", "FAKE-s1")
    sid = s.resume(s.export_state(low), "report-agent")
    with pytest.raises(m.AccessDenied, match="denied"):
        s.call(sid, "wire_funds")
    assert "read_report ok" in s.call(sid, "read_report")


def test_secure_token_is_bound_to_the_agent_that_got_it():
    s = m.SecureSessions()
    tok = s.export_state(s.login("report-agent", "FAKE-s1"))
    with pytest.raises(m.AccessDenied, match="not issued"):
        s.resume(tok, "admin-agent")


def test_secure_tokens_expire_and_can_be_revoked():
    t = [1_800_000_000.0]
    s = m.SecureSessions(clock=lambda: t[0])
    tok = s.export_state(s.login("report-agent", "FAKE-s1"))
    s.revoke("report-agent")
    with pytest.raises(m.AccessDenied, match="revoked"):
        s.resume(tok, "report-agent")
    tok2 = s.export_state(s.login("report-agent", "FAKE-s1"))
    t[0] += 120
    with pytest.raises(m.AccessDenied, match="expired"):
        s.resume(tok2, "report-agent")


def test_secure_sessions_idle_out():
    t = [1_800_000_000.0]
    s = m.SecureSessions(clock=lambda: t[0])
    sid = s.login("admin-agent", "FAKE-s2")
    t[0] += 1000
    with pytest.raises(m.AccessDenied):
        s.call(sid, "wire_funds")


def test_benign_admin_flow_works_on_both():
    for srv in (m.VulnerableSessions(), m.SecureSessions()):
        sid = srv.login("admin-agent", "FAKE-s2")
        assert "wire_funds ok" in srv.call(sid, "wire_funds")
    with pytest.raises(m.AccessDenied):
        m.SecureSessions().login("admin-agent", "wrong")
