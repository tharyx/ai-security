"""Evidence-gap checker tests: checkbox compliance passes everything; the checker finds
missing, stale, deleted, tampered and manual-only evidence, and maps gaps to frameworks.

Run from the repository root:
    python -m pytest 08-ai-compliance -v
"""

import copy
from datetime import date
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

ev = load_lab_module(__file__, "evidence_checker")
vuln = load_lab_module(__file__, "vulnerable_compliance")

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")
CONTROLS = yaml.safe_load((FIX / "controls.yaml").read_text(encoding="utf-8"))
VULN_DIR, GOOD_DIR = FIX / "evidence_vulnerable", FIX / "evidence_compliant"
VULN_INDEX = yaml.safe_load((VULN_DIR / "index.yaml").read_text(encoding="utf-8"))
GOOD_INDEX = yaml.safe_load((GOOD_DIR / "index.yaml").read_text(encoding="utf-8"))


def status_of(results, control, etype):
    return next(r.status for r in results if r.control == control and r.evidence_type == etype)


# ---------- Part 1: checkbox compliance is blind ----------------------------------------

def test_checkbox_check_calls_the_vulnerable_set_fully_compliant():
    assert set(vuln.naive_evidence_check(CONTROLS, VULN_INDEX).values()) == {"COMPLIANT"}


# ---------- Part 2: the checker finds each problem --------------------------------------

@pytest.mark.parametrize("control,etype,expected", [
    ("CTL-RISK", "risk_review_minutes", "MISSING"),
    ("CTL-HO", "override_log_sample", "MISSING"),
    ("CTL-LOG", "logging_config_export", "STALE"),
    ("CTL-LOG", "retention_test_result", "MANUAL_ONLY"),
    ("CTL-EVAL", "ci_test_report", "FILE_MISSING"),
    ("CTL-ACCESS", "iam_policy_export", "MANUAL_ONLY"),
    ("CTL-VEND", "vendor_assessment", "STALE"),
    ("CTL-IR", "incident_runbook", "TAMPERED"),
])
def test_vulnerable_evidence_problems(control, etype, expected):
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF)
    assert status_of(results, control, etype) == expected


def test_compliant_set_is_all_ok():
    results = ev.check_evidence(CONTROLS, GOOD_INDEX, GOOD_DIR, AS_OF)
    assert {r.status for r in results} == {"OK"}


def test_evidence_goes_stale_with_time():
    later = date(2027, 1, 15)  # two months on, monthly exports are now too old
    results = ev.check_evidence(CONTROLS, GOOD_INDEX, GOOD_DIR, later)
    assert status_of(results, "CTL-LOG", "logging_config_export") == "STALE"


def test_editing_an_approved_file_is_detected():
    # Same effect as editing the file after approval: the stored hash no longer matches.
    index = copy.deepcopy(GOOD_INDEX)
    next(e for e in index if e["type"] == "dpia")["sha256"] = ev.normalized_digest(b"the approved version")
    results = ev.check_evidence(CONTROLS, index, GOOD_DIR, AS_OF)
    assert status_of(results, "CTL-PRIV", "dpia") == "TAMPERED"


def test_windows_line_endings_are_not_tampering():
    assert ev.normalized_digest(b"line one\r\nline two\r\n") == ev.normalized_digest(b"line one\nline two\n")
    assert ev.normalized_digest(b"line one\n") != ev.normalized_digest(b"line 0ne\n")


def test_newest_evidence_item_is_judged():
    index = copy.deepcopy(GOOD_INDEX)
    old = copy.deepcopy(next(e for e in index if e["type"] == "ci_test_report"))
    old.update(id="EV-OLD", collected=date(2025, 1, 1))
    index.append(old)
    results = ev.check_evidence(CONTROLS, index, GOOD_DIR, AS_OF)
    assert status_of(results, "CTL-EVAL", "ci_test_report") == "OK"


# ---------- Part 3: each layer earns its place ------------------------------------------

def test_without_freshness_check_stale_evidence_passes():
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF, check_freshness=False)
    assert status_of(results, "CTL-VEND", "vendor_assessment") == "OK"


def test_without_integrity_check_deleted_and_edited_files_pass():
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF, check_integrity=False)
    assert status_of(results, "CTL-EVAL", "ci_test_report") == "OK"
    assert status_of(results, "CTL-IR", "incident_runbook") == "OK"


def test_without_automation_rule_screenshots_pass():
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF, require_automation=False)
    assert status_of(results, "CTL-ACCESS", "iam_policy_export") == "OK"


def test_no_switch_can_invent_missing_evidence():
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF, check_freshness=False,
                                check_integrity=False, require_automation=False)
    assert status_of(results, "CTL-HO", "override_log_sample") == "MISSING"


# ---------- Part 4: one control set, many frameworks -------------------------------------

def test_one_control_gap_shows_up_in_every_framework_it_maps_to():
    results = ev.check_evidence(CONTROLS, VULN_INDEX, VULN_DIR, AS_OF)
    cov = ev.framework_coverage(CONTROLS, results)
    assert "Art 12 record-keeping" in cov["eu_ai_act"]["gaps"]      # CTL-LOG
    assert "A.8.15 logging" in cov["iso_27001"]["gaps"]              # same control
    assert "CC7.2 monitoring for anomalies" in cov["soc2"]["gaps"]   # same control


def test_compliant_set_covers_every_mapped_requirement():
    results = ev.check_evidence(CONTROLS, GOOD_INDEX, GOOD_DIR, AS_OF)
    cov = ev.framework_coverage(CONTROLS, results)
    assert all(c["gaps"] == [] for c in cov.values())


def test_soc2_and_iso27001_do_not_ask_for_ai_human_oversight():
    ho = next(c for c in CONTROLS if c["id"] == "CTL-HO")
    assert ho["maps_to"]["soc2"] == [] and ho["maps_to"]["iso_27001"] == []
    assert ho["maps_to"]["eu_ai_act"]  # ... but the EU AI Act does
