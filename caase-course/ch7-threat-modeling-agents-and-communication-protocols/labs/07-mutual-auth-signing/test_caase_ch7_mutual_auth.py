from __future__ import annotations

import pytest

from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "secure_channel")


@pytest.mark.parametrize("proto", sc.PROTOCOLS)
def test_mutual_handshake_and_signed_messages_for_each_protocol(proto):
    a, b = sc.make_hmac_pair()
    ca, sb = sc.connect(a, b, proto)
    assert ca.sid == sb.sid and ca.suite == "hmac-sha256" and ca.proto == proto
    assert sb.receive(ca.send({"x": 1})) == {"x": 1}
    assert ca.receive(sb.send({"y": 2})) == {"y": 2}


def test_server_with_wrong_key_fails_authentication():
    a, b = sc.make_hmac_pair()
    b.hmac_keys["agent-a"] = b"FAKE-some-other-secret"
    with pytest.raises(sc.HandshakeError, match="server failed"):
        sc.connect(a, b, "a2a")


def test_client_impersonator_fails_the_finish_step():
    a, b = sc.make_hmac_pair()
    a.hmac_keys["agent-b"] = b"FAKE-wrong"  # attacker does not know the real pairwise secret
    with pytest.raises(sc.HandshakeError):
        sc.connect(a, b, "a2a")


def test_tampered_body_is_rejected():
    a, b = sc.make_hmac_pair()
    ca, sb = sc.connect(a, b, "a2a")
    env = ca.send({"amount": 10})
    env["body"] = {"amount": 10000}
    with pytest.raises(sc.MessageError, match="bad signature"):
        sb.receive(env)


def test_replay_and_staleness_are_refused():
    t = [1_800_000_000.0]
    a, b = sc.make_hmac_pair(clock=lambda: t[0])
    ca, sb = sc.connect(a, b, "a2a")
    env = ca.send({"n": 1})
    sb.receive(env)
    with pytest.raises(sc.MessageError, match="replayed"):
        sb.receive(env)
    old = ca.send({"n": 2})
    t[0] += 3600
    with pytest.raises(sc.MessageError, match="stale"):
        sb.receive(old)


def test_cross_protocol_replay_is_refused():
    a, b = sc.make_hmac_pair()
    a2a_c, a2a_s = sc.connect(a, b, "a2a")
    ucp_c, ucp_s = sc.connect(a, b, "ucp")
    env = a2a_c.send({"task": "pay"})
    with pytest.raises(sc.MessageError, match="wrong protocol"):
        ucp_s.receive(env)
    # even if the attacker relabels the protocol, the signature covers it
    relabelled = dict(env, proto="ucp")
    with pytest.raises(sc.MessageError):
        ucp_s.receive(relabelled)


def test_wrong_recipient_is_refused():
    a, b = sc.make_hmac_pair()
    ca, sb = sc.connect(a, b, "a2a")
    env = ca.send({"x": 1})
    env["to"] = "agent-c"
    with pytest.raises(sc.MessageError, match="sender or recipient"):
        sb.receive(env)


def test_policy_floor_refuses_a_downgrade_to_none():
    a, b = sc.make_hmac_pair(floor="hmac-sha256")
    with pytest.raises(sc.HandshakeError, match="floor"):
        sc.connect(a, b, "a2a", mitm=sc.Mitm(strip_to=["none"]))


def test_without_a_floor_an_unauthenticated_none_suite_can_be_forced_and_that_is_the_risk():
    a, b = sc.make_hmac_pair(floor="none")
    ca, sb = sc.connect(a, b, "a2a", mitm=sc.Mitm(strip_to=["none"]))
    assert ca.suite == "none"  # the reply was unsigned, so the attacker repaired it: floor=none is a downgrade hole


def test_transcript_binding_detects_stripping_even_when_the_floor_would_allow_the_weaker_suite():
    a, b = sc.make_hmac_pair(floor="none")
    with pytest.raises(sc.HandshakeError, match="downgrade detected"):
        sc.connect(a, b, "ucp", mitm=sc.Mitm(strip_to=["hmac-sha256"]))  # 'none' stripped, hmac kept: list altered


def test_none_suite_authenticates_nothing():
    a, b = sc.make_hmac_pair(floor="none")
    a.supported = ["none"]
    b.supported = ["none"]
    ca, sb = sc.connect(a, b, "a2a")
    forged = {"proto": "a2a", "sid": sb.sid, "from": "agent-a", "to": "agent-b", "ts": a.clock(), "nonce": "n", "body": {"evil": 1}, "sig": ""}
    assert sb.receive(forged) == {"evil": 1}  # accepted: this is why a policy floor matters


def test_ed25519_mutual_auth_signing_and_downgrade_protection():
    pytest.importorskip("cryptography")
    a, b = sc.make_ed25519_pair()
    ca, sb = sc.connect(a, b, "a2a")
    assert ca.suite == "ed25519"
    assert sb.receive(ca.send({"ok": True})) == {"ok": True}
    # the verifier holds only PUBLIC keys: b cannot sign as a
    assert not hasattr(b, "ed_private") or b.ed_private is not a.ed_private
    # floor allows hmac; attacker strips ed25519 so peers would fall back to hmac: transcript binding catches it
    a, b = sc.make_ed25519_pair(floor="hmac-sha256")
    with pytest.raises(sc.HandshakeError, match="downgrade detected"):
        sc.connect(a, b, "ucp", mitm=sc.Mitm(strip_to=["none", "hmac-sha256"]))
    # relying party with floor ed25519 refuses anything weaker
    a2, b2 = sc.make_ed25519_pair(floor="ed25519")
    b2.supported = ["none", "hmac-sha256"]
    with pytest.raises(sc.HandshakeError):
        sc.connect(a2, b2, "acp")


def test_ed25519_forged_signature_from_other_key_fails():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    a, b = sc.make_ed25519_pair()
    ca, sb = sc.connect(a, b, "a2a")
    env = ca.send({"x": 1})
    attacker = Ed25519PrivateKey.generate()
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    env["sig"] = attacker.sign(sc.canon(unsigned)).hex()
    with pytest.raises(sc.MessageError, match="bad signature"):
        sb.receive(env)
