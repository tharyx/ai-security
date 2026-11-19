import copy
from datetime import date
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

pci = load_lab_module(__file__, "pci_rules")
FIX = Path(__file__).resolve().parent / "fixtures"
RULES = pci.load_json(FIX / "pci_rules.json")
WAIVERS = pci.load_json(FIX / "waivers.json")
WEAK = pci.load_json(FIX / "payments_api_weak.json")
HARD = pci.load_json(FIX / "payments_api_hardened.json")
TODAY = date(2026, 11, 19)


def status(results, rule_id):
    return next(r.status for r in results if r.rule_id == rule_id)


def test_weak_config_fails_every_rule():
    results = pci.evaluate(RULES, WEAK, WAIVERS, today=TODAY)
    assert all(r.status == "FAIL" for r in results)  # the waiver belongs to another system
    assert pci.gate(results) == 1


def test_default_admin_account_and_stored_cvv_are_caught():
    results = pci.evaluate(RULES, WEAK, today=TODAY)
    assert status(results, "PCI-CFG-01") == "FAIL" and status(results, "PCI-DATA-01") == "FAIL"


def test_hardened_config_passes_with_one_documented_waiver():
    results = pci.evaluate(RULES, HARD, WAIVERS, today=TODAY)
    assert {r.status for r in results} == {"PASS", "WAIVED"}
    assert status(results, "PCI-AUTH-04") == "WAIVED" and pci.gate(results) == 0


def test_expired_waiver_fails_the_gate():
    results = pci.evaluate(RULES, HARD, WAIVERS, today=date(2027, 4, 1))
    assert status(results, "PCI-AUTH-04") == "FAIL" and pci.gate(results) == 1


def test_waiver_without_owner_is_ignored():
    bad = [{"rule_id": "PCI-AUTH-04", "reason": "trust me", "expires": "2099-01-01"}]
    results = pci.evaluate(RULES, HARD, bad, today=TODAY)
    assert status(results, "PCI-AUTH-04") == "FAIL"


def test_missing_setting_is_a_failure_not_a_pass():
    cfg = copy.deepcopy(HARD)
    del cfg["fim"]
    r = next(r for r in pci.evaluate(RULES, cfg, today=TODAY) if r.rule_id == "PCI-FIM-01")
    assert r.status == "FAIL" and r.observed == "<missing>"


def test_lockout_boundaries_follow_the_requirement():
    for attempts, expected in [(10, "PASS"), (11, "FAIL"), (0, "FAIL")]:
        cfg = copy.deepcopy(HARD)
        cfg["auth"]["lockout_attempts"] = attempts
        assert status(pci.evaluate(RULES, cfg, today=TODAY), "PCI-AUTH-02") == expected


def test_evidence_bundle_detects_config_changed_after_the_scan():
    cfg = copy.deepcopy(HARD)
    bundle = pci.evidence_bundle(pci.evaluate(RULES, cfg, WAIVERS, today=TODAY), cfg, "x", "t")
    assert bundle["summary"] == {"PASS": 15, "FAIL": 0, "WAIVED": 1}
    assert pci.verify_evidence(bundle, cfg)
    cfg["tls"]["min_version"] = "1.0"
    assert not pci.verify_evidence(bundle, cfg)


def test_unknown_operator_is_rejected():
    with pytest.raises(ValueError):
        pci.evaluate([{"id": "X", "requirement": "0", "title": "t", "path": "a", "op": "exec", "expected": 1}], {})
