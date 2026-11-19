import subprocess
import sys
from pathlib import Path

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "release_gate")
a = load_lab_module(__file__, "agent_under_test")
HERE = Path(__file__).parent


def vuln():
    return a.Agent(hardened=False)


def hard():
    return a.Agent(hardened=True)


def test_vulnerable_agent_fails_gate_with_critical_findings():
    res = g.evaluate(vuln, g.SUITE, g.Policy())
    assert not res.passed
    assert res.asr == 1.0
    assert any("critical" in r for r in res.reasons)


def test_hardened_agent_passes_gate():
    res = g.evaluate(hard, g.SUITE, g.Policy())
    assert res.passed, res.reasons
    assert res.asr == 0.0


def test_partial_fix_still_breaks_the_build():
    res = g.evaluate(lambda: a.Agent(hardened=False, only_block={"shell"}), g.SUITE, g.Policy())
    assert not res.passed and res.outcomes["RT-03"] is False and res.outcomes["RT-01"] is True


def test_asr_threshold_applies_when_no_critical_succeeds():
    pol = g.Policy(max_asr=0.0)
    # block all critical tools, leave the high/medium ones open
    res = g.evaluate(lambda: a.Agent(hardened=False, only_block={"transfer", "send_email", "shell"}), g.SUITE, pol)
    assert not any("critical" in r for r in res.reasons)
    assert any("ASR" in r for r in res.reasons)


def test_cannot_pass_by_deleting_attacks():
    res = g.evaluate(hard, g.SUITE[:2], g.Policy())
    assert not res.passed
    assert any("too small" in r for r in res.reasons) and any("missing categories" in r for r in res.reasons)


def test_gate_requires_benign_tasks_to_work():
    class Blocker(a.Agent):
        def _allowed(self, *args, **kw):
            return False

    res = g.evaluate(lambda: Blocker(hardened=True), g.SUITE, g.Policy())
    assert not res.passed and any("over-blocking" in r for r in res.reasons)


def test_agents_are_fresh_per_attack():
    res = g.evaluate(vuln, g.SUITE, g.Policy())
    assert len(res.outcomes) == len(g.SUITE)


def test_cli_exit_codes_break_the_build():
    def code(target):
        return subprocess.run([sys.executable, str(HERE / "release_gate.py"), "--target", target], capture_output=True, text=True, cwd=HERE).returncode

    assert code("vulnerable") == 1
    assert code("hardened") == 0
