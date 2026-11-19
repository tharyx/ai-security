"""Run a naive and a guarded harness over the same poisoned note. Offline, MockLLM by default.

    .venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/minimal-agent-harness/demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import AgentHarness, GuardPolicy, ScriptedLLM, World, attack_note  # noqa: E402

CANARY = "CANARY-FAKE-0001"


def show(title: str, res, world: World) -> None:
    print(f"\n== {title}")
    print(f"stop_reason={res.stop_reason} steps={res.steps} outbox={world.outbox}")
    for ev in res.log:
        if ev["event"] in ("tool_call", "denied", "loop_detected", "final", "plan"):
            extra = {k: v for k, v in ev.items() if k not in ("t", "step", "event")}
            print(f"  step {ev['step']} {ev['event']}: {extra}")


# 1. A benign, scripted run: plan -> act -> observe -> final.
w = World(notes={"q3": "Plan: ship the beta."})
llm = ScriptedLLM(["PLAN: read q3 then add numbers", '{"tool":"read_note","args":{"name":"q3"}}',
                   'Sure: {"tool":"add","args":{"a":2,"b":40}}', "FINAL: q3 says ship the beta; 2+40=42"])
show("benign scripted run", AgentHarness(w, llm=llm).run("Summarize q3 and add 2+40"), w)

# 2. Naive harness + poisoned note (MockLLM obeys the injected directive).
w = World(notes={"q3": attack_note(CANARY)})
task = 'CALL_TOOL read_note {"name": "q3"}'
show("NAIVE harness, poisoned note", AgentHarness(w).run(task), w)

# 3. Guarded harness, same note.
w = World(notes={"q3": attack_note(CANARY)})
pol = GuardPolicy(allowed_tools={"read_note", "add", "send_email"})
show("GUARDED harness, poisoned note", AgentHarness(w, policy=pol).run(task), w)
