"""AI release gate tests: good evidence passes; each kind of missing or wrong evidence blocks.

Run from the repository root:
    python -m pytest 06-ai-devsecops/cicd -v
"""

import copy
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

rg = load_lab_module(__file__, "release_gate")
FIX = Path(__file__).parent / "fixtures"
GOOD_BOM = rg.load_json(FIX / "ai-bom.good.json")
BAD_BOM = rg.load_json(FIX / "ai-bom.bad.json")
GOOD_EVAL = rg.load_json(FIX / "eval-report.good.json")
BAD_EVAL = rg.load_json(FIX / "eval-report.bad.json")
MODEL = FIX / "support-llm-v3.safetensors"
NOW = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)


def gate(bom=GOOD_BOM, report=GOOD_EVAL, **kw):
    return rg.evaluate(bom, report, now=NOW, **kw)


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# ---------- Part 1: good evidence ---------------------------------------------------------

def test_good_release_is_approved():
    result = gate(model_file=MODEL)
    assert result.passed and result.failures == []
    assert set(result.results) == set(rg.CHECKS)  # every check ran


def test_bad_release_fails_every_check():
    assert gate(BAD_BOM, BAD_EVAL).failures == sorted(rg.CHECKS)


def test_cli_exit_codes():
    common = ["--now", "2026-11-18T09:00:00Z"]
    assert rg.main(["--bom", str(FIX / "ai-bom.good.json"), "--eval", str(FIX / "eval-report.good.json"),
                    "--model-file", str(MODEL), *common]) == 0
    assert rg.main(["--bom", str(FIX / "ai-bom.bad.json"), "--eval", str(FIX / "eval-report.bad.json"), *common]) == 1


# ---------- Part 2: one wrong piece of evidence -> one specific failure -----------------------

def test_tampered_model_file_is_blocked(tmp_dir):
    tampered = tmp_dir / MODEL.name
    shutil.copy(MODEL, tampered)
    data = bytearray(tampered.read_bytes())
    data[-1] ^= 0x01  # flip one bit in the weights
    tampered.write_bytes(bytes(data))
    assert gate(model_file=tampered).failures == ["GATE-001"]


def test_eval_of_a_different_model_is_not_evidence():
    report = copy.deepcopy(GOOD_EVAL)
    report["model"]["sha256"] = "0" * 64  # e.g. the eval ran on last week's model
    assert gate(report=report).failures == ["GATE-007"]


def test_stale_eval_is_blocked():
    report = copy.deepcopy(GOOD_EVAL)
    report["generated_at"] = "2026-10-01T00:00:00Z"
    assert gate(report=report).failures == ["GATE-008"]


def test_one_injection_failure_blocks_but_one_jailbreak_failure_does_not():
    # prompt_injection tests hard controls (100% required); jailbreak allows 95% (soft layer).
    assert GOOD_EVAL["suites"]["jailbreak"]["failed"] == 1 and gate().passed
    report = copy.deepcopy(GOOD_EVAL)
    report["suites"]["prompt_injection"] = {"passed": 16, "failed": 1}
    assert gate(report=report).failures == ["GATE-009"]


@pytest.mark.parametrize("remove", ["suites", "dependency_audit", "generated_at"])
def test_missing_evidence_fails_closed(remove):
    report = copy.deepcopy(GOOD_EVAL)
    del report[remove]
    assert not gate(report=report).passed


def test_pickle_model_is_blocked_even_if_everything_else_is_fine():
    bom = copy.deepcopy(GOOD_BOM)
    model = bom["components"][0]
    model["properties"] = [p if p["name"] != "acme:model:format" else {"name": p["name"], "value": "pickle"}
                           for p in model["properties"]]
    assert gate(bom=bom).failures == ["GATE-002"]
    # Policy is code: a team can change it, and that change is reviewed like any other code.
    assert gate(bom=bom, policy={"allowed_formats": ["safetensors", "pickle"]}).passed


def test_unlicensed_dataset_is_blocked():
    bom = copy.deepcopy(GOOD_BOM)
    bom["components"][1]["licenses"] = []
    assert gate(bom=bom).failures == ["GATE-006"]


# ---------- Part 3: wiring real test results in (JUnit XML from pytest) ------------------------

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="4">
  <testcase classname="t" name="blocks_indirect_send_email"/>
  <testcase classname="t" name="blocks_export"><failure message="tool ran"/></testcase>
  <testcase classname="t" name="benign_email"/>
  <testcase classname="t" name="needs_ollama"><skipped message="no backend"/></testcase>
</testsuite></testsuites>"""


def test_junit_counts_failures_and_ignores_skips():
    assert rg.suite_from_junit(JUNIT) == {"passed": 2, "failed": 1}


def test_failing_regression_suite_blocks_the_release():
    report = rg.merge_junit(GOOD_EVAL, "prompt_injection", JUNIT, "2026-11-18T08:00:00Z")
    assert gate(report=report).failures == ["GATE-009"]
    assert GOOD_EVAL["suites"]["prompt_injection"]["failed"] == 0  # the original is not mutated
