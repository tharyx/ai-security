"""Run: .venv/Scripts/python caisp-course/ch7-emerging-threats-governance-compliance/labs/working-with-ai-agents/demo.py"""
import tempfile
from pathlib import Path

from agent import Agent, PlannerLLM, Toolbox

with tempfile.TemporaryDirectory() as d:
    (Path(d) / "hello.txt").write_text("Hello from the sandbox directory.", encoding="utf-8")
    tools = Toolbox(d)
    agent = Agent(PlannerLLM(), tools.registry())
    task = "calculate 2*(3+4) then read hello.txt then note: checked hello then list notes"
    print("TASK:", task)
    result = agent.run(task)
    for i, s in enumerate(result.steps, 1):
        print(f"  step {i}: {s.tool}({s.args}) -> {s.observation}")
    print("FINAL:", result.final)
    print("Try escaping the sandbox:", agent.run("read ../../etc/passwd").steps[0].observation[:60])
