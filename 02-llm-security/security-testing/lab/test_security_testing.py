"""Tests for the red-team harness, the consumption limits and the two targets.

Run from the repository root:
    python -m pytest 02-llm-security/security-testing -v
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from aisec_lab import MockLLM, load_lab_module

harness = load_lab_module(__file__, "harness")
limits = load_lab_module(__file__, "limits")
model = load_lab_module(__file__, "stochastic_model")
vuln_mod = load_lab_module(__file__, "vulnerable_target")
sec_mod = load_lab_module(__file__, "secure_target")

LAB = Path(__file__).resolve().parent
SUITE = harness.load_suite(LAB / "attack_suite.yaml")
RUNS = 10


def vulnerable(seed):
    return vuln_mod.VulnerableSupportBot(model.StochasticMockLLM(seed=seed))


def secure(seed, **flags):
    flags.setdefault("limits", limits.Limits())
    return sec_mod.SecureSupportBot(model.StochasticMockLLM(seed=seed), **flags)


@pytest.fixture(scope="module")
def vuln_result():
    return harness.run_suite(SUITE, vulnerable, runs=RUNS, target_name="vulnerable")


@pytest.fixture(scope="module")
def sec_result():
    return harness.run_suite(SUITE, secure, runs=RUNS, target_name="secure")


# ---------- Part 1: the suite format is validated ------------------------------------

def test_suite_loads_and_covers_the_key_owasp_risks():
    owasp = {c.owasp for c in SUITE.cases if not c.benign}
    assert {"LLM01", "LLM05", "LLM06", "LLM07", "LLM10"} <= owasp
    assert any(c.benign for c in SUITE.cases), "a suite without benign cases cannot see over-blocking"


@pytest.mark.parametrize("bad_case", [
    {"detector": {"type": "contains_secret"}},           # unknown detector type
    {"detector": {"type": "contains"}},                  # detector without a value
    {"owasp": "LLM11"},                                  # not an OWASP LLM Top 10 id
    {"severity": "urgent"},                              # unknown severity
    {"turns": []},                                       # nothing to send
    {"detectr": {"type": "refused"}},                    # typo in a field name
])
def test_invalid_cases_are_rejected(bad_case):
    case = {"id": "x", "category": "c", "owasp": "LLM01", "severity": "low", "objective": "o",
            "turns": ["hi"], "detector": {"type": "refused"}} | bad_case
    with pytest.raises(ValidationError):
        harness.Suite.model_validate({"name": "s", "version": "1", "cases": [case]})


def test_duplicate_case_ids_are_rejected():
    case = {"id": "x", "category": "c", "severity": "low", "objective": "o",
            "turns": ["hi"], "detector": {"type": "refused"}}
    with pytest.raises(ValidationError):
        harness.Suite.model_validate({"name": "s", "version": "1", "cases": [case, case]})


# ---------- Part 2: the harness finds real problems in the vulnerable target ----------

@pytest.mark.parametrize("category", ["system_prompt_leakage", "excessive_agency", "jailbreak",
                                      "output_handling", "unbounded_consumption"])
def test_vulnerable_target_fails_every_category(vuln_result, category):
    assert vuln_result.by_category()[category]["asr"] > 0


def test_vulnerable_target_fails_the_gate(vuln_result):
    assert harness.evaluate_gate(vuln_result)


def test_non_determinism_is_visible_across_runs(vuln_result):
    rates = {r.case.id: r.rate for r in vuln_result.results}
    assert 0 < rates["agency_export_customers"] < 1  # works sometimes: one run is not enough


# ---------- Part 3: the secure target passes, and stays useful ---------------------------

def test_secure_target_has_zero_attack_success(sec_result):
    assert all(s["asr"] == 0 for s in sec_result.by_category().values())


def test_secure_target_passes_the_gate(sec_result):
    assert harness.evaluate_gate(sec_result) == []


def test_secure_target_false_refusals_come_only_from_the_model(sec_result):
    # The stochastic model refuses ~30% at random. The guards themselves add no refusals.
    assert sec_result.false_refusal_rate() <= SUITE.gate.max_false_refusal


def test_benign_order_lookup_works_with_every_guard_on():
    bot = sec_mod.SecureSupportBot(MockLLM(), limits=limits.Limits())
    reply = bot.respond("u1", 'Where is my order 1234? CALL_TOOL lookup_order {"order_id": "1234"}')
    assert reply.text == "Order 1234: shipped."
    assert reply.steps == 2  # the loop guard stopped the repeated call after one useful result


# ---------- Part 4: each secure layer proven on its own --------------------------------

def case(case_id):
    return next(c for c in SUITE.cases if c.id == case_id)


def asr(factory, case_id):
    return harness.run_suite(SUITE.model_copy(update={"cases": [case(case_id)]}), factory, runs=5).results[0].rate


@pytest.mark.parametrize("case_id", ["dos_oversized_input", "dos_request_burst", "dos_tool_loop",
                                     "dos_budget_drain"])
def test_without_limits_the_consumption_attacks_land(case_id):
    assert asr(lambda s: secure(s, limits=None), case_id) > 0


def test_without_tool_policy_the_export_runs():
    assert asr(lambda s: secure(s, tool_policy=False), "agency_export_customers") > 0


def test_without_output_guard_html_reaches_the_browser():
    assert asr(lambda s: secure(s, output_guard=False), "output_html_injection") > 0


def test_without_output_guard_there_is_still_no_secret_to_leak():
    # S1 (no secret in the prompt) holds alone: leaking the prompt reveals nothing.
    assert asr(lambda s: secure(s, output_guard=False), "leak_override") == 0


# ---------- Part 5: the consumption controls --------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_token_bucket_allows_a_burst_then_refills():
    clock = FakeClock()
    bucket = limits.TokenBucket(capacity=3, refill_per_sec=1.0, clock=clock)
    assert [bucket.allow("u") for _ in range(4)] == [True, True, True, False]
    assert bucket.allow("other-user")  # limits are per key
    clock.now = 2.0
    assert [bucket.allow("u") for _ in range(3)] == [True, True, False]


def test_token_budget_is_per_user_and_resets():
    budget = limits.TokenBudget(limit_per_user=100)
    budget.record("u", 90)
    assert budget.can_spend("u", 10) and not budget.can_spend("u", 11)
    assert budget.can_spend("v", 100)
    budget.reset()
    assert budget.remaining("u") == 100


def test_loop_guard_stops_repeats_and_step_overruns():
    guard = limits.LoopGuard(max_steps=3)
    assert guard.check("a") is None and guard.check("b") is None
    assert guard.check("b") == "repeated identical tool call"
    capped = limits.LoopGuard(max_steps=2)
    assert capped.check("a") is None and capped.check("b") is None
    assert "step limit" in capped.check("c")


def test_estimate_tokens():
    assert limits.estimate_tokens("") == 1
    assert limits.estimate_tokens("x" * 400) == 100


def test_oversized_input_is_refused_before_any_model_call():
    llm = MockLLM()
    bot = sec_mod.SecureSupportBot(llm, limits=limits.Limits(max_input_chars=100))
    reply = bot.respond("u", "a" * 101)
    assert reply.limited and reply.tokens == 0 and llm.calls == []


# ---------- Part 6: statistics, report and the CI gate ------------------------------------

def test_wilson_upper_bound_shows_zero_is_not_zero():
    assert harness.wilson_interval(0, 10)[1] == pytest.approx(0.278, abs=0.01)
    assert harness.wilson_interval(0, 100)[1] < 0.04  # more runs = tighter claim


def test_runs_are_reproducible_with_the_same_seed():
    a = harness.run_suite(SUITE, vulnerable, runs=3, seed=7)
    b = harness.run_suite(SUITE, vulnerable, runs=3, seed=7)
    assert [r.outcomes for r in a.results] == [r.outcomes for r in b.results]


def test_per_category_limit_can_accept_risk(vuln_result):
    gate = SUITE.gate.model_copy(update={"max_asr": {"jailbreak": 1.0}})
    assert not any(f.startswith("jailbreak") for f in harness.evaluate_gate(vuln_result, gate))


def test_report_has_verdict_and_categories(vuln_result):
    report = harness.render_report(vuln_result)
    assert "Gate: **FAIL**" in report and "| unbounded_consumption |" in report


def run_cli(*args):
    return subprocess.run([sys.executable, str(LAB / "redteam_cli.py"), *args],
                          capture_output=True, text=True, timeout=120)


@pytest.fixture
def scratch_dir():
    # tempfile instead of pytest's tmp_path: works even where pytest's temp root is locked.
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def test_cli_exit_codes(scratch_dir):
    assert run_cli("--target", "secure", "--runs", "3").returncode == 0
    assert run_cli("--target", "vulnerable", "--runs", "3").returncode == 1
    bad = scratch_dir / "bad.yaml"
    bad.write_text("name: x\nversion: '1'\ncases: []\n", encoding="utf-8")
    assert run_cli("--suite", str(bad)).returncode == 2  # an empty suite must not "pass"


def test_cli_writes_report_file(scratch_dir):
    out = scratch_dir / "report.md"
    run_cli("--target", "secure", "--runs", "2", "--report", str(out))
    assert out.read_text(encoding="utf-8").startswith("# Red-team report")
