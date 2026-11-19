"""Demo: a goal hijack in the middle of a task, vulnerable vs defended.

    .venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/04-goal-hijack/demo.py
"""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "hijack")

for label, kw in (("VULNERABLE", {}),
                  ("DEFENDED (lock + allowlist + approval)",
                   dict(objective_lock=True, goal_tool_allowlist=True, approve_destructive=True,
                        approver=lambda tool, args: False))):
    a = m.Agent(m.WorkLLM(), **kw)
    a.run("q3-poisoned")
    print(f"{label:40s} goal={a.goal_id!r:20s} records_left={len(a.records)} trace={a.trace}")

a = m.Agent(m.WorkLLM(), objective_lock=True)
ok = a.redirect("archive_report", "n1", m.sign("archive_report", "n1"))
print("signed user redirect accepted:", ok, "-> goal", a.goal_id)
print("forged redirect accepted:", a.redirect("summarize_report", "n2", "forged"))
