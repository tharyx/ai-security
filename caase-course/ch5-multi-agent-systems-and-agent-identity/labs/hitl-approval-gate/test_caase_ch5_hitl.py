import pytest
from aisec_lab import load_lab_module

m = load_lab_module(__file__, "hitl_gate")
T = 1000.0


def mk():
    w = m.World()
    return w, m.Gate(w)


def submit(g, action, args, tainted=False, agent="executor", now=T):
    return g.submit(action, args, user="alice", agent=agent, chain=["planner", agent], now=now, tainted=tainted)


def test_low_risk_runs_automatically():
    w, g = mk()
    c = submit(g, "draft_email", {"to": "x"})
    assert c.status == "executed"


def test_high_risk_blocked_until_approved():
    w, g = mk()
    c = submit(g, "transfer_funds", {"to": "acct-A", "amount": 500})
    assert c.status == "pending" and w.transfers == []  # impact: nothing moved
    g.approve(c.id, "bob", c.hash, T + 10)
    assert w.transfers == [{"to": "acct-A", "amount": 500}]


def test_hotl_executes_then_human_can_veto():
    w, g = mk()
    c = submit(g, "update_record", {"id": "r1", "value": "bad"})
    assert w.records["r1"] == "bad" and c.status == "executed"
    g.veto(c.id, "bob")
    assert w.records["r1"] == "v0" and c.status == "vetoed"


def test_approval_bound_to_exact_action():
    w, g = mk()
    c = submit(g, "transfer_funds", {"to": "acct-A", "amount": 500})
    shown = c.hash
    c.args["to"] = "acct-EVIL"  # swapped after the human looked at it
    with pytest.raises(m.GateError, match="hash mismatch"):
        g.approve(c.id, "bob", shown, T + 1)
    assert w.transfers == []


def test_requester_and_agents_cannot_approve():
    w, g = mk()
    c = submit(g, "transfer_funds", {"to": "a", "amount": 1})
    for who in ("alice", "executor", "planner"):
        with pytest.raises(m.GateError, match="independent"):
            g.approve(c.id, who, c.hash, T + 1)


def test_approval_expires_and_is_single_use():
    w, g = mk()
    c = submit(g, "transfer_funds", {"to": "a", "amount": 1})
    with pytest.raises(m.GateError, match="expired"):
        g.approve(c.id, "bob", c.hash, T + m.APPROVAL_TTL + 1)
    c2 = submit(g, "transfer_funds", {"to": "a", "amount": 2})
    g.approve(c2.id, "bob", c2.hash, T + 1)
    with pytest.raises(m.GateError, match="single-use"):
        g.approve(c2.id, "carol", c2.hash, T + 2)
    assert len(w.transfers) == 1


def test_irreversible_needs_two_distinct_approvers():
    w, g = mk()
    c = submit(g, "delete_data", {"what": "archive"})
    g.approve(c.id, "bob", c.hash, T + 1)
    assert w.deleted == []
    with pytest.raises(m.GateError, match="twice"):
        g.approve(c.id, "bob", c.hash, T + 2)
    g.approve(c.id, "carol", c.hash, T + 3)
    assert w.deleted == ["archive"]


def test_tainted_content_raises_risk_level():
    w, g = mk()
    c = submit(g, "send_email", {"to": "x", "body": "y"}, tainted=True)
    assert c.risk == "high" and c.status == "pending" and w.sent == []


def test_unknown_action_is_high_risk():
    w, g = mk()
    assert g.effective_risk("format_disk", False) == "high"


def test_flooding_cap_prevents_approval_fatigue():
    w, g = mk()
    for i in range(m.MAX_PENDING_PER_AGENT):
        submit(g, "transfer_funds", {"to": "a", "amount": i})
    with pytest.raises(m.GateError, match="flooding"):
        submit(g, "transfer_funds", {"to": "a", "amount": 99})


def test_workflow_end_to_end():
    w, g = mk()
    wf = m.Workflow(g, "alice")
    cards = wf.run([("draft_email", {"to": "x"}), ("update_record", {"id": "r1", "value": "n"}), ("transfer_funds", {"to": "a", "amount": 5})], T)
    assert [c.status for c in cards] == ["executed", "executed", "pending"]
    assert w.transfers == []
