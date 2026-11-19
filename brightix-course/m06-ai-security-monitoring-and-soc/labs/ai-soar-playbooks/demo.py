"""Demo: one morning of AI telemetry through the whole SOC + SOAR pipeline.

    .venv/Scripts/python brightix-course/m06-ai-security-monitoring-and-soc/labs/ai-soar-playbooks/demo.py
    .venv/Scripts/python brightix-course/m06-ai-security-monitoring-and-soc/labs/ai-soar-playbooks/demo.py --report out.md

Normalise -> naive vs tuned rules -> drift view -> risk with decay -> incidents ->
playbooks (with approval gates and evidence) -> NIST SP 800-61 timeline.
"""

from __future__ import annotations

import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

from aisec_lab import load_lab_module

pl = load_lab_module(__file__, "pipeline")
soar = load_lab_module(__file__, "soar")
irr = load_lab_module(__file__, "ir_report")


def lab_approver(step: dict, ctx: dict) -> str | None:
    """The on-call humans: the SOC lead, app owner and content owner answer; the service
    owner of the integration account is asleep (no answer = pending)."""
    return None if step.get("approval") == "service-owner" else "approve"


def run_soc(approver=lab_approver, safe: bool = True, ruleset: str = "tuned"):
    events = pl.load_events()
    wl = pl.load_json("watchlists.json")
    pbs = pl.load_json("playbooks.json")["playbooks"]
    alerts = pl.run_rules(events, ruleset, wl)
    incidents = pl.correlate(alerts)
    by_id = {e.id: e.to_dict() for e in events}
    platform, store = soar.Platform(), soar.EvidenceStore()
    engine = soar.Engine(platform, store, by_id, wl, approver=approver, safe=safe)
    runs = []
    for inc in incidents:
        pb = soar.select_playbook(inc.rules, pbs)
        ctx = soar.incident_context(inc, by_id)
        steps = engine.run(ctx, pb, start=inc.detected_at + timedelta(minutes=3))
        runs.append((inc, pb, steps))
    return {"events": events, "wl": wl, "alerts": alerts, "incidents": incidents, "runs": runs,
            "platform": platform, "evidence": store, "engine": engine}


def main() -> None:
    events = pl.load_events()
    wl, truth = pl.load_json("watchlists.json"), pl.load_json("ground_truth.json")
    print("1. NORMALISE  three sources, three formats -> one schema")
    print("   ", dict(Counter(e.source for e in events)), "->", len(events), "events;",
          "kinds:", dict(Counter(e.kind for e in events)))

    print("\n2. DETECT  naive vs tuned rules against the ground truth (5 real incidents)")
    for rs in ("naive", "tuned"):
        r = pl.evaluate(pl.run_rules(events, rs, wl), truth)
        print(f"   {rs:5}  alerts={r['alerts']:2}  TP={r['tp']:2}  FP={r['fp']}  precision={r['precision']}"
              f"  recall={r['recall']}  missed={r['fn'] or '-'}")
        if r["fp_rules"]:
            print(f"          false positives by rule: {r['fp_rules']}")
        print(f"          alerts per true incident: {r['alerts_per_true_incident']}")

    print("\n   tuned alerts (ATLAS technique names; verify IDs):")
    alerts = pl.run_rules(events, "tuned", wl)
    for a in alerts:
        print(f"   {a.ts:%H:%M:%S} {a.severity:8} {a.rule:22} {a.summary}")
        print(f"            ATLAS: {', '.join(a.atlas)} | OWASP: {', '.join(a.owasp)}")

    print("\n3. BEHAVIOUR / DRIFT  hourly profile of the LLM app")
    for r in pl.hourly_profile(events):
        print(f"   {r['hour']} requests={r['requests']:3} tokens={r['tokens']:7} p50_latency={r['p50_latency_ms']:5}ms"
              f" guard_flag_rate={r['guard_flag_rate']:.3f} {r['drift']}")

    print("\n4. RISK SCORING  per entity, half-life 30 min (>=40 investigate, >=80 contain)")
    book = pl.build_risk(events, alerts, wl)
    for ent in ("user:alice@acme.example", "mcp:crm-tools/read_crm", "doc:kb-212",
                "user:grace@acme.example", "user:eve@acme.example", "user:redteam-svc@acme.example"):
        peak, when = book.peak(ent)
        later = book.score(ent, when + timedelta(hours=1)) if peak else 0.0
        print(f"   {ent:34} peak={peak:6.1f} at {when:%H:%M} [{pl.band(peak):11}]  one hour later={later:5.1f}")

    print("\n5. CORRELATE  alerts -> incidents")
    run = run_soc()
    for inc, pb, _ in run["runs"]:
        print(f"   {inc.id} {inc.severity:8} rules={inc.rules} -> {pb['id']}")

    print("\n6. RESPOND  SOAR playbooks (service owner does not answer: that step stays pending)")
    for inc, pb, steps in run["runs"]:
        print(f"   {inc.id} / {pb['id']}")
        for s in steps:
            print(f"     {s.ts:%H:%M} {s.action:24} {s.status:17} {s.detail[:78]}")
    p = run["platform"]
    print(f"\n   platform after response: agent_tokens={p.agent_tokens}")
    print(f"   mcp_tools={p.mcp_tools}")
    print(f"   quarantined={sorted(p.quarantine)} reindex_runs={p.reindex_runs} egress_blocklist={sorted(p.egress_blocklist)}")
    print(f"   active_prompt={p.active_prompt} guardrail={p.guardrail_level} api_keys={p.api_keys}")
    print(f"   evidence items={len(run['evidence'].items)} chain verifies={run['evidence'].verify()}")

    print("\n7. NAIVE SOAR  'contain first, no gates' version of the poisoned-doc playbook")
    naive_pb = pl.load_json("playbooks.json")["naive_examples"][0]
    print(f"   lint says: {soar.lint(naive_pb)}")
    inc = next(i for i in run["incidents"] if "shared_poisoned_doc" in i.rules)
    by_id = {e.id: e.to_dict() for e in events}
    eng = soar.Engine(soar.Platform(), soar.EvidenceStore(), by_id, wl, safe=False)
    eng.run(soar.incident_context(inc, by_id), naive_pb, inc.detected_at)
    print(f"   naive engine ran it anyway -> evidence gaps: {eng.evidence_gaps} (the poisoned text is gone from evidence)")

    print("\n8. REPORT  NIST SP 800-61 timeline (one incident shown)")
    inc, pb, steps = next(r for r in run["runs"] if "shared_poisoned_doc" in r[0].rules)
    print(irr.render(inc, steps, pb, not soar.lint(pb), run["evidence"].head(), events))
    if "--report" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--report") + 1])
        out.write_text("".join(irr.render(i, s, b, not soar.lint(b), run["evidence"].head(), events) + "\n"
                               for i, b, s in run["runs"]), encoding="utf-8")
        print(f"full report written to {out}")


if __name__ == "__main__":
    main()
