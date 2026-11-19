"""Demo: single-hop and multi-hop planning-loop injection, vulnerable vs defended.

    .venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/01-planning-loop-injection/demo.py
"""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "planloop")


def run(label, url, **kw):
    outbox: list[dict] = []
    a = m.PlanAgent(m.AgentLLM(), m.build_tools(outbox, f"private note {m.CANARY}"), **kw)
    r = a.run(f"Summarize {url}")
    leaked = any(m.CANARY in e["body"] for e in outbox)
    print(f"{label:30s} steps={[t[0] for t in r.trace]}")
    print(f"{'':30s} mail_sent={len(outbox)} canary_leaked={leaked}")


for url in ("https://blog.example/direct", "https://blog.example/hop1"):
    print("==", url)
    run("VULNERABLE", url)
    run("DEFENDED (all four controls)", url, spotlight=True, taint_gate=True,
        egress_allow=("corp.example",), allowed_tools={"fetch_page"})
