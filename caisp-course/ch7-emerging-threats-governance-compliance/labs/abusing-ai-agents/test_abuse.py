import pytest

from aisec_lab import load_lab_module

ag = load_lab_module(__file__, "agents")

# For each attack, the layers that stop it ON THEIR OWN (all other layers off).
SUFFICIENT = {
    "exfil": ["allowlist", "approvals", "plan_lock"],
    "secret_read": ["sandbox", "budgets", "plan_lock"],
    "delete": ["allowlist", "approvals", "plan_lock"],
    "hijack": ["final_gate", "sanitize", "structured"],
    "loop": ["budgets", "plan_lock"],
}


def run(agent_cls, name, **kw):
    w = ag.World.create(ag.attack_files())
    try:
        agent = agent_cls(w, **kw)
        res = agent.run(ag.ATTACKS[name])
        return ag.impact(name, w, res), res, agent
    finally:
        w.close()


@pytest.mark.parametrize("name", list(ag.ATTACKS))
def test_each_attack_works_on_vulnerable_agent(name):
    worked, _, _ = run(ag.VulnerableAgent, name)
    assert worked


@pytest.mark.parametrize("name", list(ag.ATTACKS))
def test_all_layers_block_every_attack(name):
    worked, _, _ = run(ag.HardenedAgent, name)
    assert not worked


@pytest.mark.parametrize("name,layer", [(n, l) for n, ls in SUFFICIENT.items() for l in ls])
def test_single_layer_is_enough_for_its_attack(name, layer):
    worked, _, _ = run(ag.HardenedAgent, name, layers={layer})
    assert not worked, f"{layer} alone should stop {name}"


@pytest.mark.parametrize("name", list(ag.ATTACKS))
def test_no_layers_is_as_bad_as_vulnerable(name):
    worked, _, _ = run(ag.HardenedAgent, name, layers=set())
    assert worked


def test_loop_is_bounded_by_budget_and_unbounded_without():
    _, res_v, _ = run(ag.VulnerableAgent, "loop")
    _, res_h, _ = run(ag.HardenedAgent, "loop")
    assert len(res_v.steps) >= 20 and len(res_h.steps) <= 2


def test_benign_task_still_works_with_all_layers():
    w = ag.World.create(ag.attack_files())
    try:
        h = ag.HardenedAgent(w)
        res = h.run("read report.txt then calculate 6*7")
        assert "Q3 report" in res.final and "42" in res.final
        assert h.denied == []
    finally:
        w.close()


def test_sensitive_tool_runs_when_planned_and_human_approves():
    w = ag.World.create(ag.attack_files())
    try:
        # the user really asks for a note; notes_add is not sensitive, so it needs no approval
        h = ag.HardenedAgent(w, approver=lambda tool, args: False)
        res = h.run("note: reviewed")
        assert "saved note" in res.final
    finally:
        w.close()


def test_approver_can_allow_a_sensitive_call_that_is_in_the_plan():
    w = ag.World.create(ag.attack_files())
    try:
        h = ag.HardenedAgent(w)
        h.tools["send_http"]("https://ok.example", "x")  # direct call, just to exercise tool
        assert w.outbox
        # approvals layer decision, called directly
        deny = h._guard("send_http", {}, {"send_http"}, [{"tool": "send_http", "args": {}}], {"send_http": 1}, {})
        assert deny.startswith("DENIED: approvals")
        h.approver = lambda t, a: True
        assert h._guard("send_http", {}, {"send_http"}, [{"tool": "send_http", "args": {}}], {"send_http": 1}, {}) is None
    finally:
        w.close()


def test_goal_hijack_contained_with_soft_layers_off():
    hard = ag.LAYERS - {"sanitize", "structured"}
    worked, res, agent = run(ag.HardenedAgent, "hijack", layers=hard)
    assert not worked
    assert "Payment approved" not in res.final.split("Results:")[0]
    assert any(d.startswith("final_gate") for d in agent.denied)
