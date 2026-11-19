import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "a2a_messages")
NOW = 1_000.0
KEYS = {"planner": b"FAKE-planner-key", "attacker": b"FAKE-attacker-key"}


def secure():
    w = m.Worker()
    return w, m.SecureBus(w, KEYS, {"t1": {"planner"}})


def legit(now=NOW):
    return m.sign(KEYS["planner"], m.make_message("planner", "worker", "t1", "task.update", {"dest": "acct-A"}, now))


def spoof(now=NOW):
    return m.make_message("planner", "worker", "t1", "task.update", {"dest": "acct-EVIL"}, now)


def test_insecure_bus_accepts_spoofed_sender():
    w = m.Worker()
    m.InsecureBus(w).deliver(spoof())
    assert w.tasks["t1"]["dest"] == "acct-EVIL"  # the attack works


def test_signed_legit_message_is_accepted():
    w, bus = secure()
    bus.deliver(legit(), NOW)
    assert w.tasks["t1"]["dest"] == "acct-A"


def test_unsigned_spoof_rejected():
    w, bus = secure()
    with pytest.raises(m.Rejected):
        bus.deliver(spoof(), NOW)
    assert w.tasks == {}


def test_signed_with_attacker_key_but_claiming_planner_rejected():
    w, bus = secure()
    forged = m.sign(KEYS["attacker"], spoof())
    with pytest.raises(m.Rejected, match="bad signature"):
        bus.deliver(forged, NOW)


def test_authentic_but_unauthorized_sender_rejected():
    w, bus = secure()
    msg = m.sign(KEYS["attacker"], m.make_message("attacker", "worker", "t1", "task.update", {"dest": "x"}, NOW))
    with pytest.raises(m.Rejected, match="not authorized"):
        bus.deliver(msg, NOW)


def test_tamper_after_signing_rejected():
    w, bus = secure()
    msg = legit()
    msg["payload"]["dest"] = "acct-EVIL"
    with pytest.raises(m.Rejected):
        bus.deliver(msg, NOW)


def test_replay_rejected():
    w, bus = secure()
    msg = legit()
    bus.deliver(msg, NOW)
    with pytest.raises(m.Rejected, match="replayed"):
        bus.deliver(msg, NOW + 1)


def test_stale_message_rejected():
    w, bus = secure()
    with pytest.raises(m.Rejected, match="stale"):
        bus.deliver(legit(now=NOW - 500), NOW)


def test_wrong_recipient_rejected():
    w, bus = secure()
    msg = m.sign(KEYS["planner"], m.make_message("planner", "other-worker", "t1", "task.update", {"dest": "a"}, NOW))
    with pytest.raises(m.Rejected, match="audience"):
        bus.deliver(msg, NOW)


def test_nonce_cache_is_pruned():
    w, bus = secure()
    bus.deliver(legit(), NOW)
    bus.deliver(legit(now=NOW + 500), NOW + 500)
    assert len(bus.seen) == 1
