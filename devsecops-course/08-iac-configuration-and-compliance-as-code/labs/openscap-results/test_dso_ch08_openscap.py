from pathlib import Path

import pytest

from aisec_lab import load_lab_module

sr = load_lab_module(__file__, "scap_results")
FIX = Path(__file__).parent / "fixtures"
BEFORE = sr.parse_results(FIX / "arf_before.xml")
AFTER = sr.parse_results(FIX / "arf_after.xml")


def test_parses_target_profile_and_rules():
    assert BEFORE.target == "app-01.example"
    assert BEFORE.profile.endswith("profile_standard")
    assert len(BEFORE.rules) == 18
    first = BEFORE.rules[0]
    assert first.short == "sshd_disable_root_login" and first.severity == "high" and first.title.startswith("Disable SSH")


def test_flat_score_matches_declared_score():
    s = sr.score(BEFORE)
    assert s["matches_declared"] and s["flat_score"] == BEFORE.declared_score
    assert s["counts"]["notapplicable"] == 1 and s["counts"]["informational"] == 1


def test_excluded_results_do_not_count():
    s = sr.score(BEFORE)
    # 6 pass, 9 fail/error; notapplicable, notchecked and informational are excluded
    assert s["flat_score"] == pytest.approx(100 * 6 / 15, abs=0.01)


def test_error_counts_as_failure():
    assert "package_aide_installed" in [r.short for r in sr.failing(BEFORE)]


def test_severity_weighted_is_lower_when_high_rules_fail():
    s = sr.score(BEFORE)
    assert s["severity_weighted_score"] < 50 and s["failed_by_severity"]["high"] == 4


def test_failing_sorted_worst_first():
    sev = [r.severity for r in sr.failing(BEFORE)]
    assert sev == sorted(sev, key={"high": 0, "medium": 1, "low": 2}.get)


def test_after_remediation_is_better_and_fixed_counts_as_success():
    assert sr.score(AFTER)["flat_score"] > sr.score(BEFORE)["flat_score"]
    assert sr.score(AFTER)["counts"]["fixed"] == 1


def test_compare_lists_improvements_and_remaining():
    c = sr.compare(BEFORE, AFTER)
    assert "sshd_disable_root_login" in c["improved"] and "accounts_password_minlen_login_defs" in c["improved"]
    assert c["still_failing"] == ["mount_option_tmp_nodev"] and c["regressed"] == []
    assert c["delta_flat"] > 0


def test_tampered_declared_score_is_detected():
    text = (FIX / "arf_before.xml").read_text().replace(f">{BEFORE.declared_score}<", ">99.0<")
    scan = sr.parse_results(text.encode())
    assert sr.score(scan)["matches_declared"] is False


def test_doctype_entities_rejected():
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><TestResult/>'
    with pytest.raises(ValueError):
        sr.parse_results(evil)


def test_missing_testresult_is_an_error():
    with pytest.raises(ValueError):
        sr.parse_results(b"<root/>")
