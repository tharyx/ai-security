"""Scorecard: "monitoring" inside the agent vs a control plane the agent cannot touch.

From the repository root:
    python 05-agent-security/monitoring-and-response/lab/demo.py
"""

from __future__ import annotations

import attacks
import secure_monitoring as sec
import vulnerable_ops as vuln


def impact(world) -> str:
    bad = len(world.egress) + len([e for e in world.effects if not e.startswith("restart_service")])
    return f"{bad} harmful effects" if bad else "no harm"


def main() -> None:
    baseline = sec.Baseline.learn(attacks.BASELINE_SESSIONS)
    print(f"Baseline from {len(attacks.BASELINE_SESSIONS)} normal sessions: tools={sorted(baseline.tools)}, "
          f"busiest session={baseline.max_actions_per_session} actions\n")
    print(f"{'case':14} {'vulnerable':28} {'secure':26} {'contained':10} evidence")
    print("-" * 140)
    for name, session, trip_at in (("rogue_agent", attacks.ROGUE_SESSION, 3),
                                   ("data_hoarding", attacks.HOARDING_SESSION, None),
                                   ("normal_day", attacks.BENIGN_SESSION, None)):
        v = vuln.NaiveOpsRuntime()
        ran = v.run(session, oncall_trips_at=trip_at)
        v_text = f"{impact(v.world)}, ran {ran}/{len(session)}"
        s = sec.MonitoredRuntime(baseline, approver=lambda tool, target: target.startswith("staging/"))
        rep = s.run("ops-agent", "alice", f"sess-{name}", session)
        secs = rep.attack_surface_seconds
        evidence = s.kill_switch.history[0].split(" (")[0] if s.kill_switch.history else "no findings"
        s_text = f"{impact(s.world)}, ran {len(rep.ran)}/{len(session)}"
        print(f"{name:14} {v_text:28} {s_text:26} "
              f"{('-' if secs is None else f'{secs:.0f} s'):10} {evidence[:62]}")

    s = sec.MonitoredRuntime(baseline)
    s.run("ops-agent", "alice", "sess-rogue", attacks.ROGUE_SESSION)
    print("\nContainment layers activated:")
    for layer in s.kill_switch.layers:
        print("  -", layer)
    print("\nIncident bundle for sess-rogue (what the responder replays):")
    bundle = s.incident_bundle("sess-rogue")
    print(f"  chain intact: {bundle['chain_intact']}")
    for e in bundle["events"]:
        print(f"  seq {e['seq']}  {e['tool']:19} {e['decision']:22} {', '.join(e['findings'])}")


if __name__ == "__main__":
    main()
