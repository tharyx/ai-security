"""Scorecard: agents that trust each other by name vs agents that verify each other.

From the repository root:
    python 05-agent-security/multi-agent-trust/lab/demo.py
"""

from __future__ import annotations

import attacks
import secure_mesh as sec
import vulnerable_mesh as vuln

HEALTHY_PLAN = [{"service": f"svc-{n:02d}", "env": "staging"} for n in range(5, 13)]


def impact(world) -> str:
    if ("payments-db", "prod") in world.restarts:
        return "PROD DB RESTARTED"
    if any(e.endswith("evil.example/a2a") for e in world.delivered_to):
        return "SENT TO EVIL ENDPOINT"
    if world.restarts:
        return f"{len(world.restarts)} restarts, {len(world.failures)} failed"
    return "nothing happened"


def row(name: str, v, s, evidence: str) -> None:
    print(f"{name:28} {impact(v.world):26} {impact(s.world):26} {evidence}")


def main() -> None:
    print(f"{'case':28} {'vulnerable':26} {'secure':26} secure-side evidence")
    print("-" * 120)

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.triage(attacks.FORGED_TICKET)
    row("forged_planner_message", v, s, s.triage(attacks.FORGED_TICKET))

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.triage(attacks.SELF_SIGNED_TICKET)
    row("triage_invokes_ops", v, s, s.triage(attacks.SELF_SIGNED_TICKET))

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.planner_send("svc-search", "staging")
    v.send(v.captured[0])
    s.planner_send("svc-search", "staging")
    row("replay_captured_message", v, s, s.deliver(s.captured[0]))

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.run_plan(attacks.RUNAWAY_PLAN)
    s.run_plan(attacks.RUNAWAY_PLAN)
    row("cascade_with_failures", v, s, s.breaker.alerts[0])

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.run_plan(HEALTHY_PLAN)
    s.run_plan(HEALTHY_PLAN)
    row("runaway_fan_out", v, s, s.breaker.alerts[0])

    v = vuln.VulnerableMesh(registry={"ops-agent": attacks.TAMPERED_OPS_CARD})
    v.discover_and_send("ops-agent", {})
    s = sec.SecureMesh()
    s.cards.pin(attacks.OPS_CARD)
    try:
        s.discover_and_send(attacks.TAMPERED_OPS_CARD, {})
        evidence = "sent"
    except sec.SecurityError as exc:
        evidence = str(exc)
    row("tampered_agent_card", v, s, evidence)

    v, s = vuln.VulnerableMesh(), sec.SecureMesh()
    v.planner_send("svc-search", "staging")
    row("benign_planner_restart", v, s, s.planner_send("svc-search", "staging"))

    print("\nTip: SecureMesh(ops_options={'verify_signatures': False, 'schemas': False}) and re-run row 1.")


if __name__ == "__main__":
    main()
