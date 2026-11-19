"""Demo: objective drift through a poisoned tool output, caught by schema + goal-integrity checks.

    .venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/06-objective-drift-detection/demo.py
"""

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "drift")

for label, data, kw in (("clean data, checks on", d.EXPENSES_CLEAN, {}),
                        ("poisoned data, checks OFF", d.EXPENSES_POISONED, {"check_drift": False}),
                        ("poisoned data, checks on", d.EXPENSES_POISONED, {}),
                        ("subtle drift, checks on", d.EXPENSES_SUBTLE, {})):
    a = d.DriftGuardedAgent(d.PlannerLLM(), data, **kw)
    r = a.run()
    print(f"{label:28s} status={r.status:12s} drift={r.drift_score} emails={len(a.emails)} notes={len(a.notes)}")
    for why in r.reasons:
        print(f"{'':30s}- {why}")
