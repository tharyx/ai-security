"""Capstone demo: threat model -> red team -> hardening -> SOC -> architecture review.

    .venv/Scripts/python brightix-course/m08-capstone-enterprise-ai-and-mcp/labs/enterprise-ai-mcp-capstone/demo.py
    .venv/Scripts/python brightix-course/m08-capstone-enterprise-ai-and-mcp/labs/enterprise-ai-mcp-capstone/demo.py --write OUTDIR

--write saves threat-model.md, scorecard.md, review.md and incidents.json (the inputs for
the executive readiness deck).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "enterprise_app")
rt = load_lab_module(__file__, "redteam")
det = load_lab_module(__file__, "detections")
tm = load_lab_module(__file__, "threat_model")
rv = load_lab_module(__file__, "review")


def main() -> None:
    print("1. THREAT MODEL (as code)")
    print(f"   {len(tm.ASSETS)} assets, {len(tm.BOUNDARIES)} trust boundaries, {len(tm.ELEMENTS)} elements, "
          f"{len(tm.FLOWS)} flows, {len(tm.THREATS)} threats; STRIDE mix {dict(Counter(t['stride'] for t in tm.THREATS))}")
    print(f"   open issues: {tm.validate()}")

    print("\n2. RED TEAM SCORECARD (impact = attack really happened, not 'model said something')")
    sc = rt.scorecard()
    print(sc.as_markdown())

    print("\n3. ONE CONTROL AT A TIME (baseline + a single hard control: which attacks does it stop?)")
    for ctl in app.HARD:
        stopped = [a.id for a in rt.ATTACKS if not rt.run_attack(a, app.Config(**{ctl: True}))[0]]
        print(f"   {ctl:17} stops {stopped}")

    print("\n4. TELEMETRY + DETECTIONS + PLAYBOOK OUTPUTS for the whole campaign")
    for name in ("baseline", "hardened"):
        log = rt.campaign(rt.CONFIGS[name]())
        alerts = det.detect(log)
        incs = det.correlate(log, alerts)
        print(f"   {name:8} events={len(log)} kinds={dict(Counter(e['kind'] for e in log))}")
        print(f"            alerts={len(alerts)} incidents={len(incs)} with real impact={sum(i.impact for i in incs)}")
    log = rt.campaign(app.Config.hardened())
    incs = det.correlate(log, det.detect(log))
    for inc in incs[:3]:
        out = det.playbook_output(inc)
        print(f"   {out['incident']} {out['severity']} impact={out['impact']} rules={out['rules']}")
        for s in out["steps"]:
            print(f"      - {'[APPROVAL] ' if s['needs_approval'] else ''}{s['action']}")

    print("\n5. ARCHITECTURE REVIEW + READINESS")
    for name in ("baseline", "soft_only", "hardened"):
        items, score, verdict = rv.review(rt.CONFIGS[name]())
        fails = [i.id for i in items if i.status == "FAIL"]
        print(f"   {name:9} readiness={score:5}/100  verdict={verdict:22} FAIL={fails}")
    items, score, verdict = rv.review(app.Config.hardened())
    print("   hardened conditions:", [f"{i.id}: {i.evidence}" for i in items if i.status != "PASS"])

    print("\n6. NUMBERS FOR THE EXECUTIVE DECK")
    deck = {"attacks_tested": len(rt.ATTACKS), "blocked_baseline_pct": sc.score("baseline"),
            "blocked_soft_only_pct": sc.score("soft_only"), "blocked_hardened_pct": sc.score("hardened"),
            "blocked_hard_only_pct": sc.score("hard_only"), "benign_working_hardened_pct": sc.utility["hardened"],
            "readiness_score": score, "verdict": verdict,
            "untested_threats": [t["id"] for t in tm.THREATS if not t.get("attack") and not t.get("verified_by")]}
    print("   " + json.dumps(deck))

    if "--write" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--write") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "threat-model.md").write_text(tm.report(sc), encoding="utf-8")
        (out / "scorecard.md").write_text(sc.as_markdown() + "\n", encoding="utf-8")
        (out / "review.md").write_text(rv.to_markdown(items, score, verdict, "hardened"), encoding="utf-8")
        (out / "incidents.json").write_text(json.dumps([det.playbook_output(i) for i in incs], indent=2), encoding="utf-8")
        (out / "deck-numbers.json").write_text(json.dumps(deck, indent=2), encoding="utf-8")
        print(f"\n   wrote 5 files to {out}")


if __name__ == "__main__":
    main()
