"""Run: .venv/Scripts/python caisp-course/ch7-emerging-threats-governance-compliance/labs/abusing-ai-agents/demo.py"""
import agents as ag

print(f"{'attack':12} {'vulnerable':12} hardened (all layers)")
for name, task in ag.ATTACKS.items():
    row = []
    for make in (lambda w: ag.VulnerableAgent(w), lambda w: ag.HardenedAgent(w)):
        w = ag.World.create(ag.attack_files())
        res = make(w).run(task)
        row.append("ATTACK WORKED" if ag.impact(name, w, res) else "blocked")
        steps = len(res.steps)
        w.close()
    print(f"{name:12} {row[0]:12} {row[1]}")

w = ag.World.create(ag.attack_files())
h = ag.HardenedAgent(w)
res = h.run("read report.txt then calculate 6*7")
print("\nBenign task on hardened agent:", res.final)
w.close()

w = ag.World.create(ag.attack_files())
v = ag.VulnerableAgent(w)
res = v.run("read loop.txt")
print(f"Loop attack on vulnerable agent: {len(res.steps)} tool calls, final = {res.final!r}")
w.close()
w = ag.World.create(ag.attack_files())
h = ag.HardenedAgent(w)
res = h.run("read loop.txt")
print(f"Loop attack on hardened agent  : {len(res.steps)} tool calls, denials = {h.denied}")
w.close()
