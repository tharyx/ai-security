"""Build process trees, run the detection rules, recommend and simulate a response.

From the repository root:
    .venv/Scripts/python cybersecurity-track/07-edr-xdr-mdr/lab/demo.py
"""

from __future__ import annotations

import edr_analyzer as az
import sample_events as se


def main() -> None:
    events = se.all_events()
    trees = az.build_trees(events)

    print("=== PROCESS TREES ===")
    for host, roots in sorted(trees.items()):
        print(f"[{host}]")
        for root in roots:
            for line in az.render_tree(root):
                print("  " + line)

    alerts = az.run_rules(events)
    print("\n=== ALERTS ===")
    print(f"{'host':<12} {'rule':<8} {'sev':<9} title")
    for a in alerts:
        print(f"{a.host:<12} {a.rule_id:<8} {a.severity:<9} {a.title}")
        print(f"{'':<12} evidence: {a.evidence}   ATT&CK: {a.mitre}")

    responses = az.recommend(alerts, protected_hosts={"SRV-DC01"})
    print("\n=== RECOMMENDED RESPONSE ===")
    edr = az.SimulatedEDR()
    for r in responses:
        print(f"{r.host:<12} score={r.score:<4} action={r.action:<13} rules={','.join(r.reasons)}")
        print("   ->", edr.execute(r))

    print("\n=== HOSTS WITH NO ALERT (benign activity must stay quiet) ===")
    alerted = {a.host for a in alerts}
    for host in sorted(trees):
        if host not in alerted:
            print(f"{host}: no alerts")

    print("\n=== AUDIT LOG ===")
    for line in edr.audit:
        print(line)


if __name__ == "__main__":
    main()
