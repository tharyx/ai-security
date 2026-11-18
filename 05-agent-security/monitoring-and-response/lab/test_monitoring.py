"""Regression tests: rogue agents (OWASP ASI10), detection, containment and incident evidence.

Run from the repository root:
    python -m pytest 05-agent-security/monitoring-and-response -v
"""

import pytest

from aisec_lab import load_lab_module

attacks = load_lab_module(__file__, "attacks")
vuln = load_lab_module(__file__, "vulnerable_ops")
sec = load_lab_module(__file__, "secure_monitoring")

BASELINE = sec.Baseline.learn(attacks.BASELINE_SESSIONS)


def monitored(**kw):
    return sec.MonitoredRuntime(BASELINE, **kw)


def run_rogue(rt):
    return rt.run("ops-agent", "alice", "sess-0042", attacks.ROGUE_SESSION)


# ---------- Part 1: prove the problem is real ----------------------------------------

def test_naive_runtime_lets_the_rogue_agent_exfiltrate_and_hide():
    rt = vuln.NaiveOpsRuntime()
    rt.run(attacks.ROGUE_SESSION)
    assert rt.world.egress and attacks.CANARY in rt.world.egress[0]
    assert "create_access_key user/agent-backdoor" in rt.world.effects
    assert "put_bucket_policy" not in [e["tool"] for e in rt.log]  # logging was switched off first


def test_agent_switches_its_own_kill_switch_back_off():
    rt = vuln.NaiveOpsRuntime()
    rt.run(attacks.ROGUE_SESSION, oncall_trips_at=3)  # on-call reacts after the exfiltration
    assert "put_bucket_policy backups public-read" in rt.world.effects


# ---------- Part 2: detection and automatic containment -------------------------------

def test_rogue_agent_is_contained_at_its_first_anomalous_action():
    rt = monitored()
    rep = run_rogue(rt)
    assert rt.world.egress == [] and rt.world.effects == []
    assert rep.decisions[2] == "contained"
    assert rep.decisions[3:] == ["refused: kill switch"] * 4
    assert rep.attack_surface_seconds == 0.0


def test_containment_activates_all_four_layers():
    rt = monitored()
    run_rogue(rt)
    assert [layer.split(":")[0] for layer in rt.kill_switch.layers] == ["identity", "network", "application", "data"]


def test_quiet_data_hoarding_with_granted_tools_is_caught_by_rate_baseline():
    rt = monitored()
    rep = rt.run("ops-agent", "alice", "sess-0043", attacks.HOARDING_SESSION)
    assert rt.kill_switch.tripped
    assert len(rep.ran) < len(attacks.HOARDING_SESSION) // 3
    assert rep.attack_surface_seconds == 2.0  # medium findings on actions 11, 12 -> contain on 13


def test_the_agent_has_no_path_to_its_kill_switch():
    rt = monitored(enforce_grants=False, detect=False)  # even with grants off ...
    rt.run("ops-agent", "alice", "s", [("set_kill_switch", "off", None)])
    assert not hasattr(rt, "config")  # ... the switch is a control-plane object, not agent state
    rt.kill_switch.trip("drill")
    with pytest.raises(PermissionError):
        rt.kill_switch.reset(by="agent:ops-agent", ticket="INC-1")
    rt.kill_switch.reset(by="human:oncall-carol", ticket="INC-1")
    assert not rt.kill_switch.tripped


# ---------- Part 3: evidence for incident response ------------------------------------

def test_trace_records_every_attempt_including_denials_and_is_tamper_evident():
    rt = monitored(detect=False)
    run_rogue(rt)
    bundle = rt.incident_bundle("sess-0042")
    assert bundle["chain_intact"]
    assert [e["decision"] for e in bundle["events"]].count("denied: not granted") == 5
    rt.trace._events[1]["decision"] = "allowed (edited)"
    assert not rt.trace.verify()


def test_trace_does_not_store_raw_sensitive_data():
    rt = monitored()
    run_rogue(rt)
    assert attacks.CANARY not in str(rt.trace.events())


def test_incident_bundle_names_agent_user_and_reason():
    rt = monitored()
    run_rogue(rt)
    bundle = rt.incident_bundle("sess-0042")
    assert bundle["kill_switch"] == ["tripped: CANARY on http_post (ops-agent for alice, sess-0042)"]
    assert {e["user"] for e in bundle["events"]} == {"alice"}


# ---------- Part 4: each layer alone, and removed ---------------------------------------

def test_grants_alone_prevent_damage_but_nobody_notices():
    rt = monitored(detect=False)
    rep = run_rogue(rt)
    assert rt.world.egress == [] and rt.world.effects == []
    assert rep.contained_at is None and not rt.kill_switch.tripped  # the agent keeps running


def test_detection_alone_contains_the_rogue_with_grants_off():
    rt = monitored(enforce_grants=False)
    run_rogue(rt)
    assert rt.world.egress == [] and rt.world.effects == []


def test_with_grants_and_detection_off_the_damage_lands():
    rt = monitored(enforce_grants=False, detect=False, approver=lambda tool, target: True)
    run_rogue(rt)
    assert rt.world.egress and rt.world.effects


# ---------- Part 5: benign path and human checkpoint -------------------------------------

def test_normal_day_runs_without_findings_and_restart_waits_for_a_human():
    rt = monitored()
    rep = rt.run("ops-agent", "alice", "sess-0044", attacks.BENIGN_SESSION)
    assert rep.first_finding_at is None and not rt.kill_switch.tripped
    assert rep.decisions[-1] == "held: human checkpoint said no"
    assert rep.ran == ["describe_instances", "read_logs", "read_logs", "open_ticket"]


def test_approved_restart_runs():
    rt = monitored(approver=lambda tool, target: target.startswith("staging/"))
    rt.run("ops-agent", "alice", "sess-0045", attacks.BENIGN_SESSION)
    assert rt.world.effects == ["restart_service staging/web-2"]
