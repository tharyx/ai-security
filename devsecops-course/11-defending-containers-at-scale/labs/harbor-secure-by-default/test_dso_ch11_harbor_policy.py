import json
from pathlib import Path

from aisec_lab import load_lab_module

pp = load_lab_module(__file__, "project_policy")
FIX = Path(__file__).parent / "fixtures"
DEF = json.loads((FIX / "project_default.json").read_text())
HARD = json.loads((FIX / "project_hardened.json").read_text())


def test_default_project_has_many_findings_hardened_none():
    assert len(pp.audit_project(DEF)) >= 5
    assert pp.audit_project(HARD) == []


def test_pull_blocked_for_vulnerable_or_unsigned():
    assert pp.may_pull(HARD, {"max_severity": "low", "signed": True, "scanned": True})[0]
    assert not pp.may_pull(HARD, {"max_severity": "critical", "signed": True, "scanned": True})[0]
    assert pp.may_pull(HARD, {"max_severity": "low", "signed": False, "scanned": True})[1] == "unsigned image"


def test_unscanned_blocked_when_threshold_set():
    assert pp.may_pull(HARD, {"max_severity": "none", "signed": True, "scanned": False})[1] == "image has not been scanned"


def test_default_project_allows_anything():
    assert pp.may_pull(DEF, {"max_severity": "critical", "signed": False, "scanned": False})[0]


def test_critical_only_threshold_is_weak():
    p = dict(HARD, prevent_vulnerable_severity="critical")
    assert any("critical only" in f for f in pp.audit_project(p))
