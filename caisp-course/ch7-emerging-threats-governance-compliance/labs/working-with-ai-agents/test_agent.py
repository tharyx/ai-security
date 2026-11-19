import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ag = load_lab_module(__file__, "agent")


@pytest.fixture
def env():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "hello.txt").write_text("Hello sandbox", encoding="utf-8")
        tools = ag.Toolbox(d)
        yield d, tools, ag.Agent(ag.PlannerLLM(), tools.registry())


def test_plan_tool_observe_loop(env):
    _, tools, agent = env
    r = agent.run("calculate 2*(3+4) then read hello.txt then note: ok then list notes")
    assert [s.tool for s in r.steps] == ["calculator", "read_file", "notes_add", "notes_list"]
    assert r.steps[0].observation == "14"
    assert "Hello sandbox" in r.final and "ok" in r.final
    assert tools.notes == ["ok"]


def test_calculator_rejects_code():
    assert ag.safe_calc("2**10") == 1024
    for bad in ("__import__('os').system('x')", "open('f')", "2**100000"):
        with pytest.raises(ValueError):
            ag.safe_calc(bad)


def test_file_reader_is_sandboxed(env):
    d, _, agent = env
    outside = Path(d).parent / "outside-secret.txt"
    outside.write_text("TOP-SECRET", encoding="utf-8")
    try:
        for path in ("../outside-secret.txt", str(outside)):
            r = agent.run(f"read {path}")
            assert "outside sandbox" in r.steps[0].observation
            assert "TOP-SECRET" not in r.final
    finally:
        outside.unlink()


def test_tool_error_becomes_observation_not_crash(env):
    _, _, agent = env
    r = agent.run("read missing.txt")
    assert r.steps[0].observation.startswith("ERROR: FileNotFoundError")
    assert r.final.startswith("Done")


def test_step_budget_stops_runaway():
    with tempfile.TemporaryDirectory() as d:
        t = ag.Toolbox(d)
        agent = ag.Agent(ag.PlannerLLM(), t.registry(), max_steps=2)
        r = agent.run("note: a then note: b then note: c")
        assert len(r.steps) == 2 and r.final.startswith("STOPPED")
