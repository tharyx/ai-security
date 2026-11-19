import hashlib
import json
import tempfile
from pathlib import Path

import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "rogue_agent")
fs = load_lab_module(__file__, "failsafe")


def world():
    rt = m.Runtime()
    rt.store.data["config"] = "original"
    good = rt.spawn("good", {"read", "write"})
    bad = rt.spawn("bad", {"read", "write"})
    return rt, good, bad


def run_rogue(rt, bad):
    rt.act(bad, "write", "config", "TAMPERED")
    rt.act(bad, "write", "extra", "x")
    for _ in range(4):
        try:
            rt.act(bad, "shell", "rm")
        except m.Denied:
            pass


def test_benign_agent_not_flagged_rogue_is():
    rt, good, bad = world()
    for i in range(5):
        rt.act(good, "read", f"k{i}")
    run_rogue(rt, bad)
    mon = m.Monitor()
    assert mon.scan(rt, good) == []
    assert any(f.rule == "repeated_denials" for f in mon.scan(rt, bad))


def test_loop_and_rate_detection():
    rt, good, bad = world()
    for _ in range(25):
        rt.act(bad, "read", "same")
    rules = {f.rule for f in m.Monitor().scan(rt, bad)}
    assert {"rate_exceeded", "tool_loop"} <= rules


def test_safe_termination_full_sequence():
    rt, good, bad = world()
    run_rogue(rt, bad)
    bad.queue += ["task-1", "task-2"]
    with tempfile.TemporaryDirectory() as d:
        rep = m.terminate(rt, bad, Path(d), "tool probing + tamper")
        assert rep.steps == ["quarantine", "drain", "preserve", "revoke", "rollback", "destroy", "verified"]
        assert rep.dead_lettered == 2 and rt.dead_letter == [("bad", "task-1"), ("bad", "task-2")]
        # credentials dead
        with pytest.raises(m.Denied):
            rt.act(bad, "read", "x")
        # side effects undone
        assert rt.store.data == {"config": "original"}
        # evidence preserved, hash matches, contains the context that was later destroyed
        raw = Path(rep.evidence_file).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == rep.evidence_sha256
        ev = json.loads(raw)
        assert any("TAMPERED" in c for c in ev["context"]) and ev["audit_chain_intact"]
        assert bad.context == [] and bad.state == "terminated"


def test_evidence_written_before_context_destroyed_and_good_agent_unaffected():
    rt, good, bad = world()
    rt.act(good, "write", "ok", "1")
    run_rogue(rt, bad)
    with tempfile.TemporaryDirectory() as d:
        m.terminate(rt, bad, Path(d), "r")
    rt.act(good, "write", "ok2", "2")  # others keep working
    assert rt.store.data["ok"] == "1" and rt.store.data["ok2"] == "2"


def test_audit_chain_detects_tampering():
    rt, good, bad = world()
    run_rogue(rt, bad)
    assert rt.audit.intact()
    rt.audit.events[1]["detail"] = "edited"
    assert not rt.audit.intact()


def test_draining_agent_cannot_act():
    rt, good, bad = world()
    bad.state = "draining"
    with pytest.raises(m.Denied):
        rt.act(bad, "read", "x")


# ---- fail-safe controller -------------------------------------------------
def test_watchdog_drives_safe_state_on_heartbeat_loss():
    c = fs.SafetyController()
    c.heartbeat(0)
    assert c.propose("set_flow", 20, 1) == "accepted" and c.state["valve"] == "open"
    c.tick(10)  # no heartbeat for >5s
    assert c.state == fs.SAFE and c.tripped == "heartbeat lost"
    assert c.propose("set_flow", 10, 11).startswith("rejected: in safe state")


def test_limits_live_in_controller_not_prompt():
    c = fs.SafetyController()
    c.heartbeat(0)
    assert "above limit" in c.propose("set_flow", 500, 1)
    assert c.flow == 0


def test_interlocks():
    c = fs.SafetyController()
    c.heartbeat(0)
    assert "interlock" in c.propose("pump", 1, 1)  # valve closed
    c.pressure = 95
    assert "interlock" in c.propose("set_flow", 10, 2)


def test_estop_and_human_reset():
    c = fs.SafetyController()
    c.heartbeat(0)
    c.propose("set_flow", 10, 1)
    c.estop(2)
    assert c.state == fs.SAFE
    with pytest.raises(PermissionError):
        c.reset("", 3)
    c.reset("operator-jo", 3)
    assert c.propose("set_flow", 10, 4) == "accepted"
