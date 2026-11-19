import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "delegation_tokens")
T0 = 1000.0


def svc_root():
    s = m.TokenService()
    root = s.issue_root("alice", "orchestrator", "agent-b", ["calendar.read", "mail.send", "files.read"], 600, T0)
    return s, root


def test_root_token_verifies():
    s, root = svc_root()
    c = s.verify(root, audience="agent-b", scope="mail.send", now=T0 + 1)
    assert c["user"] == "alice" and m.act_chain(c) == ["orchestrator"]


def test_downscoping_on_each_hop():
    s, root = svc_root()
    t2 = s.exchange(root, new_agent="agent-b", aud="calendar-api", scopes=["calendar.read", "mail.send"], ttl=300, now=T0 + 1)
    t3 = s.exchange(t2, new_agent="agent-c", aud="calendar-api", scopes=["calendar.read"], ttl=300, now=T0 + 2)
    assert s.decode(t3)["scope"] == ["calendar.read"]
    with pytest.raises(m.TokenError, match="scope mail.send"):
        s.verify(t3, audience="calendar-api", scope="mail.send", now=T0 + 3)


def test_cannot_widen_scope():
    s, root = svc_root()
    t2 = s.exchange(root, new_agent="agent-b", aud="x", scopes=["calendar.read"], ttl=300, now=T0)
    with pytest.raises(m.TokenError, match="widen"):
        s.exchange(t2, new_agent="agent-c", aud="x", scopes=["calendar.read", "mail.send"], ttl=300, now=T0)


def test_audience_binding_blocks_passthrough():
    s, root = svc_root()
    t2 = s.exchange(root, new_agent="agent-b", aud="calendar-api", scopes=["calendar.read"], ttl=300, now=T0)
    with pytest.raises(m.TokenError, match="audience mismatch"):
        s.verify(t2, audience="mail-api", scope="calendar.read", now=T0 + 1)


def test_act_chain_records_every_hop():
    s, root = svc_root()
    t2 = s.exchange(root, new_agent="agent-b", aud="x", scopes=["files.read"], ttl=300, now=T0)
    t3 = s.exchange(t2, new_agent="agent-c", aud="x", scopes=["files.read"], ttl=300, now=T0)
    c = s.decode(t3)
    assert m.act_chain(c) == ["orchestrator", "agent-b", "agent-c"] and c["user"] == "alice"


def test_chain_depth_limit():
    s, root = svc_root()
    t = root
    for i in range(m.MAX_DEPTH - 1):
        t = s.exchange(t, new_agent=f"a{i}", aud="x", scopes=["files.read"], ttl=300, now=T0)
    with pytest.raises(m.TokenError, match="too deep"):
        s.exchange(t, new_agent="one-too-many", aud="x", scopes=["files.read"], ttl=300, now=T0)


def test_child_never_outlives_parent():
    s, root = svc_root()
    t2 = s.exchange(root, new_agent="agent-b", aud="x", scopes=["files.read"], ttl=99999, now=T0 + 500)
    assert s.decode(t2)["exp"] == T0 + 600


def test_expiry_enforced_and_expired_parent_cannot_exchange():
    s, root = svc_root()
    with pytest.raises(m.TokenError, match="expired"):
        s.verify(root, audience="agent-b", scope="mail.send", now=T0 + 601)
    with pytest.raises(m.TokenError, match="expired"):
        s.exchange(root, new_agent="b", aud="x", scopes=["files.read"], ttl=10, now=T0 + 601)


def test_tamper_detected():
    s, root = svc_root()
    payload, sig = root.split(".")
    forged = m._b64(m._unb64(payload).replace(b"files.read", b"admin.all")) + "." + sig
    with pytest.raises(m.TokenError, match="bad signature"):
        s.decode(forged)


def test_revocation():
    s, root = svc_root()
    s.revoke(root)
    with pytest.raises(m.TokenError, match="revoked"):
        s.verify(root, audience="agent-b", scope="mail.send", now=T0 + 1)
