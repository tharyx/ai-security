"""Governance regression tests: each failure must pass the spreadsheet and be caught by the
governed register. Assert the *outcome* (can it deploy? which finding?), not wording.

Run from the repository root:
    python -m pytest 07-ai-governance -v
"""

import copy
from datetime import date
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

sec = load_lab_module(__file__, "secure_register")
vuln = load_lab_module(__file__, "vulnerable_register")
rr = load_lab_module(__file__, "risk_register")

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")
VULN_SYSTEMS = yaml.safe_load((FIX / "systems_vulnerable.yaml").read_text(encoding="utf-8"))
GOOD_SYSTEMS = yaml.safe_load((FIX / "systems_governed.yaml").read_text(encoding="utf-8"))
GOOD_RISKS = rr.load_csv(FIX / "risks_governed.csv")
LOG = (FIX / "egress_log.txt").read_text(encoding="utf-8").splitlines()


def system(systems, sid):
    return copy.deepcopy(next(s for s in systems if s["id"] == sid))


def assess(raw, **flags):
    return sec.GovernedRegister(as_of=AS_OF, **flags).assess(raw)


# ---------- Part 1: the spreadsheet approves everything --------------------------------

@pytest.mark.parametrize("sid", ["AI-001", "AI-002", "AI-003", "AI-004", "AI-005"])
def test_spreadsheet_register_lets_every_vulnerable_system_deploy(sid):
    sheet = vuln.SpreadsheetRegister()
    sheet.load(VULN_SYSTEMS)
    assert sheet.can_deploy(sid)


def test_spreadsheet_trusts_the_declared_tier():
    row = vuln.SpreadsheetRegister().assess(system(VULN_SYSTEMS, "AI-005"))
    assert row.tier == "medium"  # it is really a prohibited use


def test_spreadsheet_calls_a_planned_control_low_risk():
    row = rr.load_csv(FIX / "risks_vulnerable.csv")[0]
    assert vuln.naive_residual(row) == "Low"


# ---------- Part 2: the governed register blocks every vulnerable system -----------------

@pytest.mark.parametrize("sid", ["AI-001", "AI-002", "AI-003", "AI-004", "AI-005"])
def test_governed_register_blocks_every_vulnerable_system(sid):
    reg = sec.GovernedRegister(as_of=AS_OF)
    reg.load(VULN_SYSTEMS, rr.load_csv(FIX / "risks_vulnerable.csv"))
    assert not reg.can_deploy(sid)


@pytest.mark.parametrize("sid,code", [
    ("AI-001", "GOV-03"),  # high risk, no human oversight
    ("AI-001", "GOV-09"),  # expired exception
    ("AI-002", "GOV-00"),  # typo in a field name fails the schema
    ("AI-003", "GOV-02"),  # intended use "TBD"
    ("AI-004", "GOV-06"),  # review overdue
    ("AI-005", "GOV-07"),  # prohibited use
])
def test_each_failure_raises_the_expected_finding(sid, code):
    assert code in assess(system(VULN_SYSTEMS, sid)).codes


def test_unowned_system_is_blocked_and_cannot_be_waived():
    raw = system(GOOD_SYSTEMS, "AI-003")
    raw["business_owner"] = ""
    raw["exceptions"] = [{"finding": "GOV-01", "reason": "owner TBC", "approved_by": "CISO",
                          "expires": date(2027, 1, 1)}]
    a = assess(raw)
    assert "GOV-01" in a.codes and a.decision == "BLOCKED"
    assert a.waived == []


def test_tier_is_computed_from_facts_not_declared():
    a = assess(system(VULN_SYSTEMS, "AI-001"))  # declared "low"
    assert a.tier == "high"
    assert any("side effects" in r for r in a.reasons)


def test_automated_hiring_decisions_are_critical_and_need_a_human_decider():
    raw = system(GOOD_SYSTEMS, "AI-002")
    raw["decision_impact"] = "automated_decision"
    raw["human_oversight"] = "sample_review"
    a = assess(raw)
    assert a.tier == "critical"
    assert "GOV-03" in a.codes
    assert {"CTL-BOARD", "CTL-APPEAL"} <= set(a.missing_controls)


def test_high_risk_system_without_a_risk_entry_is_blocked():
    reg = sec.GovernedRegister(as_of=AS_OF)
    risks = [r for r in GOOD_RISKS if r["system_id"] != "AI-002"]
    reg.load(GOOD_SYSTEMS, risks)
    assert "GOV-08" in reg.assessments["AI-002"].codes
    assert not reg.can_deploy("AI-002")


def test_unknown_system_cannot_deploy():
    reg = sec.GovernedRegister(as_of=AS_OF)
    reg.load(GOOD_SYSTEMS, GOOD_RISKS)
    assert not reg.can_deploy("AI-999")


# ---------- Part 3: benign path - governance must not block good systems ---------------

def test_every_governed_system_is_approved_or_retired():
    reg = sec.GovernedRegister(as_of=AS_OF)
    results = reg.load(GOOD_SYSTEMS, GOOD_RISKS)
    assert {a.decision for a in results} == {"APPROVED", "RETIRED"}
    assert all(not a.findings for a in results)


def test_valid_exception_waives_but_stays_visible():
    a = assess(system(GOOD_SYSTEMS, "AI-001"))
    assert a.decision == "APPROVED"
    assert [f.key for f in a.waived] == ["GOV-05:CTL-RT"]


def test_exception_stops_working_the_day_after_it_expires():
    raw = system(GOOD_SYSTEMS, "AI-001")
    later = sec.GovernedRegister(as_of=date(2027, 2, 1)).assess(raw)
    assert later.decision == "BLOCKED"
    assert {"GOV-05", "GOV-09"} <= later.codes


# ---------- Part 4: each layer proves its worth ------------------------------------------

def test_without_schema_validation_a_typo_hides_missing_oversight_but_checks_still_block():
    raw = system(VULN_SYSTEMS, "AI-002")
    a = assess(raw, validate=False)  # "human_oversite" silently dropped -> oversight "none"
    assert "GOV-00" not in a.codes
    assert "GOV-03" in a.codes      # L3 still catches the effect of the typo
    assert a.decision == "BLOCKED"


def test_without_auto_tiering_tier_gaming_succeeds():
    raw = system(VULN_SYSTEMS, "AI-001")
    raw["human_oversight"] = "none"
    raw["exceptions"] = []
    gamed = assess(raw, auto_tier=False)
    honest = assess(raw)
    assert gamed.tier == "low" and "GOV-03" not in gamed.codes
    assert honest.tier == "high" and "GOV-03" in honest.codes


def test_without_checks_everything_is_approved():
    a = assess(system(VULN_SYSTEMS, "AI-003"), checks=False)
    assert a.decision == "APPROVED" and a.findings == []


def test_without_the_gate_findings_exist_but_nothing_stops_deployment():
    reg = sec.GovernedRegister(as_of=AS_OF, gate=False)
    reg.load(VULN_SYSTEMS)
    assert reg.assessments["AI-003"].findings          # we know it is wrong ...
    assert reg.can_deploy("AI-003")                     # ... and ship it anyway


# ---------- Part 5: shadow AI -------------------------------------------------------------

def test_shadow_ai_discovery_finds_unregistered_services():
    hosts = {s["host"] for s in sec.discover_shadow_ai(LOG, VULN_SYSTEMS)}
    assert hosts == {"chat.free-ai-tool.example", "transcribe.ai-notes.example"}


def test_registering_the_meeting_notes_tool_removes_it_from_shadow_ai():
    hosts = {s["host"] for s in sec.discover_shadow_ai(LOG, GOOD_SYSTEMS)}
    assert hosts == {"chat.free-ai-tool.example"}


def test_retired_system_does_not_legitimize_its_egress():
    systems = copy.deepcopy(GOOD_SYSTEMS)
    for s in systems:
        if s["id"] == "AI-006":
            s["status"] = "retired"
    hosts = {s["host"] for s in sec.discover_shadow_ai(LOG, systems)}
    assert "transcribe.ai-notes.example" in hosts
