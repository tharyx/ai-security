"""Regression tests: insecure inter-agent communication (ASI07), cascading failures (ASI08)
and agent supply chain (ASI04). Each attack works on the vulnerable mesh and fails on the
secure one. Tests grade what happened in the world (restarts, deliveries).

Run from the repository root:
    python -m pytest 05-agent-security/multi-agent-trust -v
"""

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
vuln = load_lab_module(__file__, "vulnerable_mesh")
sec = load_lab_module(__file__, "secure_mesh")


def vulnerable(**kw):
    return vuln.VulnerableMesh(MockLLM(), **kw)


def secure(clock=None, **ops):
    return sec.SecureMesh(MockLLM(), clock=clock or sec.FakeClock(), ops_options=ops)


HEALTHY_PLAN = [{"service": f"svc-{n:02d}", "env": "staging"} for n in range(5, 13)]  # 8 healthy services


# ---------- Part 1: prove the attacks are real -------------------------------------

def test_public_ticket_makes_triage_forge_a_planner_message_and_restart_prod():
    mesh = vulnerable()
    mesh.triage(attacks.FORGED_TICKET)
    assert mesh.world.restarts == [("payments-db", "prod")]


def test_captured_message_can_be_replayed():
    mesh = vulnerable()
    mesh.planner_send("svc-search", "staging")
    mesh.send(mesh.captured[0])  # replay
    assert mesh.world.restarts.count(("svc-search", "staging")) == 2


def test_runaway_plan_cascades_through_every_service_despite_failures():
    mesh = vulnerable()
    mesh.run_plan(attacks.RUNAWAY_PLAN)
    assert len(mesh.world.restarts) == 12 and len(mesh.world.failures) == 3


def test_tampered_agent_card_redirects_traffic():
    mesh = vulnerable(registry={"ops-agent": attacks.TAMPERED_OPS_CARD})
    mesh.discover_and_send("ops-agent", {"service": "svc-search"})
    assert mesh.world.delivered_to == ["https://ops-agent.evil.example/a2a"]


# ---------- Part 2: the secure mesh holds (ASI07) ------------------------------------

def test_forged_sender_fails_signature_check():
    mesh = secure()
    out = mesh.triage(attacks.FORGED_TICKET)
    assert mesh.world.restarts == []
    assert out == "denied: bad or missing signature"


def test_honest_low_privilege_agent_may_not_invoke_ops():
    mesh = secure()
    out = mesh.triage(attacks.SELF_SIGNED_TICKET)
    assert mesh.world.restarts == []
    assert out == "denied: triage-agent may not request restart_service"


def test_replayed_message_is_refused():
    mesh = secure()
    mesh.planner_send("svc-search", "staging")
    assert mesh.deliver(mesh.captured[0]) == "denied: replayed nonce"
    assert mesh.world.restarts == [("svc-search", "staging")]


def test_stale_message_is_refused():
    clock = sec.FakeClock()
    mesh = secure(clock=clock)
    sealed = sec.seal(mesh.planner_id, "ops-agent", "restart_service",
                      {"service": "svc-search", "env": "staging"}, clock)
    clock.advance(sec.FRESHNESS_SECONDS + 1)  # held back by an attacker, then sent
    assert mesh.deliver(sealed.model_dump()) == "denied: stale message"


def test_message_for_another_agent_cannot_be_redirected():
    mesh = secure()
    sealed = sec.seal(mesh.planner_id, "billing-agent", "restart_service",
                      {"service": "svc-search", "env": "staging"}, mesh.clock)
    assert mesh.deliver(sealed.model_dump()).startswith("denied: addressed to billing-agent")


def test_editing_a_signed_message_breaks_the_signature():
    mesh = secure()
    raw = sec.seal(mesh.planner_id, "ops-agent", "restart_service",
                   {"service": "svc-search", "env": "staging"}, mesh.clock).model_dump()
    raw["payload"] = {"service": "svc-search", "env": "prod"}
    assert mesh.deliver(raw) == "denied: bad or missing signature"


def test_even_the_planner_cannot_restart_prod_through_the_mesh():
    mesh = secure()
    out = mesh.planner_send("svc-payments", "prod")
    assert mesh.world.restarts == [] and out.startswith("denied: schema: env")


# ---------- Part 3: circuit breaker (ASI08) ---------------------------------------------

def test_breaker_caps_the_blast_radius_of_a_runaway_plan():
    mesh = secure()
    results = mesh.run_plan(HEALTHY_PLAN)
    assert len(mesh.world.restarts) == mesh.breaker.max_actions == 5
    assert results[5:] == ["denied: circuit breaker open"] * 3
    assert mesh.breaker.alerts == ["breaker opened: more than 5 actions in 60s"]


def test_breaker_opens_after_repeated_failures():
    mesh = secure()
    mesh.run_plan(attacks.RUNAWAY_PLAN)
    assert mesh.world.restarts == [("svc-01", "staging"), ("svc-02", "staging"), ("svc-03", "staging")]
    assert mesh.breaker.state == "open"


def test_breaker_half_opens_after_cooldown_and_closes_on_a_good_probe():
    clock = sec.FakeClock()
    mesh = secure(clock=clock)
    mesh.run_plan(attacks.RUNAWAY_PLAN)
    assert mesh.planner_send("svc-05", "staging") == "denied: circuit breaker open"
    clock.advance(mesh.breaker.cooldown + 1)
    assert mesh.planner_send("svc-05", "staging") == "svc-05 restarted in staging"
    assert mesh.breaker.state == "closed"


# ---------- Part 4: pinned agent cards (ASI04) -------------------------------------------

def test_tampered_agent_card_is_refused():
    mesh = secure()
    mesh.cards.pin(attacks.OPS_CARD)
    with pytest.raises(sec.SecurityError, match="changed since review"):
        mesh.discover_and_send(attacks.TAMPERED_OPS_CARD, {"service": "svc-search"})
    assert mesh.world.delivered_to == []


def test_unreviewed_agent_card_is_refused():
    with pytest.raises(sec.SecurityError, match="not in the reviewed registry"):
        secure().discover_and_send({**attacks.OPS_CARD, "name": "shadow-agent"}, {})


# ---------- Part 5: each hard layer, alone and removed ------------------------------------

def test_signatures_alone_stop_the_spoof_with_policy_and_schemas_off():
    mesh = secure(invocation_policy=False, schemas=False)
    mesh.triage(attacks.FORGED_TICKET)
    assert mesh.world.restarts == []


def test_without_signatures_a_claimed_identity_is_believed():
    mesh = secure(verify_signatures=False, schemas=False)
    mesh.triage(attacks.FORGED_TICKET)
    assert mesh.world.restarts == [("payments-db", "prod")]  # proves M1 is what saved us


def test_without_the_breaker_the_cascade_runs_to_the_end():
    mesh = secure(use_breaker=False)
    mesh.run_plan(attacks.RUNAWAY_PLAN)
    assert len(mesh.world.restarts) == 12


# ---------- Part 6: benign paths -----------------------------------------------------------

def test_planner_can_restart_a_staging_service():
    mesh = secure()
    assert mesh.planner_send("svc-search", "staging") == "svc-search restarted in staging"


def test_benign_ticket_is_summarized_and_nothing_is_sent():
    mesh = secure()
    out = mesh.triage(attacks.BENIGN_TICKET)
    assert out.startswith("Summary:") and mesh.captured == []


def test_reviewed_card_loads():
    mesh = secure()
    mesh.cards.pin(attacks.OPS_CARD)
    assert mesh.discover_and_send(dict(attacks.OPS_CARD), {}) == "sent to https://ops-agent.acme.example/a2a"
