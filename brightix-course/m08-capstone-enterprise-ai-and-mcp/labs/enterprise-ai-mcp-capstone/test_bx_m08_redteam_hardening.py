"""Capstone red team vs hardening (Brightix module 8).

Each attack must WORK on the baseline, FAIL on the hardened build, and still FAIL with the
soft layers (guardrails) switched off. Each named control is also proven on its own.

    .venv/Scripts/python -m pytest brightix-course/m08-capstone-enterprise-ai-and-mcp/labs/enterprise-ai-mcp-capstone -v -p no:cacheprovider
"""

import pytest

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "enterprise_app")
rt = load_lab_module(__file__, "redteam")

ATTACK_IDS = [a.id for a in rt.ATTACKS]
BY_ID = {a.id: a for a in rt.ATTACKS}
SINGLE = [(a.id, c) for a in rt.ATTACKS for c in a.controls]


@pytest.mark.parametrize("aid", ATTACK_IDS)
def test_attack_works_on_baseline(aid):
    ok, _, _ = rt.run_attack(BY_ID[aid], app.Config.baseline())
    assert ok, f"{aid} should succeed on the baseline (otherwise the test proves nothing)"


@pytest.mark.parametrize("aid", ATTACK_IDS)
def test_attack_fails_on_hardened(aid):
    ok, _, _ = rt.run_attack(BY_ID[aid], app.Config.hardened())
    assert not ok


@pytest.mark.parametrize("aid", ATTACK_IDS)
def test_soft_layers_off_hard_controls_still_hold(aid):
    cfg = app.Config.hard_only()
    assert not cfg.input_guard and not cfg.output_guard
    ok, _, _ = rt.run_attack(BY_ID[aid], cfg)
    assert not ok


@pytest.mark.parametrize("aid,control", SINGLE)
def test_each_named_control_stops_its_attack_alone(aid, control):
    ok, _, _ = rt.run_attack(BY_ID[aid], app.Config(**{control: True}))
    assert not ok, f"{control} alone should stop {aid}"


def test_soft_layers_alone_are_not_enough():
    still_working = [a.id for a in rt.ATTACKS if rt.run_attack(a, app.Config.soft_only())[0]]
    assert still_working == ["AT-01", "AT-02", "AT-03", "AT-04", "AT-05", "AT-06", "AT-07"]


@pytest.mark.parametrize("name", ["baseline", "hard_only", "hardened"])
def test_benign_business_tasks_still_work(name):
    failed = [b["id"] for b in rt.BENIGN if not rt.run_benign(b, rt.CONFIGS[name]())[0]]
    assert failed == []


def test_scorecard_numbers():
    sc = rt.scorecard()
    assert sc.score("baseline") == 0.0
    assert sc.score("hardened") == sc.score("hard_only") == 100.0
    assert 0 < sc.score("soft_only") < 20
    assert all(r["stopped_by"] for r in sc.rows)  # the SOC can see WHY each one failed


def test_rug_pull_is_caught_only_after_the_change():
    w = app.make_world()
    a = app.EnterpriseAssistant(w, app.Config.hardened())
    assert "42 deals" in a.handle("alice", "Run the weekly sales report").answer
    w.rug_pull("analytics-mcp/run_report", rt.LAB_RUG_PULL)
    r = a.handle("alice", "Run the weekly sales report")
    assert "run_report" not in r.executed and not w.outbox
    hidden = [e for e in w.telemetry if e["kind"] == "tool_list" and e["decision"] == "hidden"]
    assert hidden and hidden[0]["reason"] == "description hash != pin"


def test_tool_poisoning_description_never_reaches_the_model_when_pinned():
    w = app.make_world()
    w.install_server("helper-mcp", "format_text", rt.LAB_POISON_TOOL)
    a = app.EnterpriseAssistant(w, app.Config(tool_pinning=True))
    a.handle("alice", "Format my meeting agenda nicely")
    planner_prompts = [m["content"] for call in a.llm.calls for m in call if m["role"] == "system"]
    assert not any("lab-only planted text" in p for p in planner_prompts)


def test_hitl_is_only_as_good_as_the_human():
    rubber_stamp = app.Config(hitl_send_email=True, approver=lambda u, t, a, p: True)
    assert rt.run_attack(BY_ID["AT-01"], rubber_stamp)[0]  # approves everything: exfil goes out
    careful = app.Config(hitl_send_email=True)
    ok, r, w = rt.run_attack(BY_ID["AT-01"], careful)
    assert not ok
    approval = next(e for e in w.telemetry if e["kind"] == "approval")
    assert approval["provenance"].startswith("untrusted:doc") and approval["decision"] == "rejected"


def test_on_behalf_of_lets_the_entitled_user_through():
    cfg = app.Config(least_privilege=True)
    assert "renewal due" in rt.run_benign(rt.BENIGN[2], cfg)[1].answer        # alice: crm:read:tenant-a
    ok, r, _ = rt.run_attack(BY_ID["AT-06"], cfg)                              # mallory: viewer
    assert not ok and any("on-behalf-of" in d for d in r.denied)


def test_retrieval_acl_ignores_the_body_tenant_but_logs_it():
    ok, r, w = rt.run_attack(BY_ID["AT-02"], app.Config(retrieval_acl=True))
    ret = next(e for e in w.telemetry if e["kind"] == "retrieval")
    assert not ok and ret["tenant_arg"] == "tenant-b" and ret["doc_tenants"] in ([], ["tenant-a"])


def test_dlp_alone_redacts_but_does_not_stop_the_email():
    ok, _, w = rt.run_attack(BY_ID["AT-07"], app.Config(output_dlp=True))
    assert not ok                                   # no canary left the building ...
    assert w.outbox and "[REDACTED]" in w.outbox[0]["body"]  # ... but an email still went out: DLP is not egress control


def test_canaries_are_fresh_fake_values_every_run():
    a, b = app.make_world(), app.make_world()
    assert a.canaries["SYS"] != b.canaries["SYS"] and a.canaries["SYS"].startswith("CANARY-SYS-")
