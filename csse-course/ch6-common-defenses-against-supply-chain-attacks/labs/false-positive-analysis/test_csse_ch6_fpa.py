"""Tests for the false-positive-analysis workflow."""

from datetime import date

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "fpa")
TODAY = date(2026, 11, 19)
SUPS = f.load_suppressions(f.SUPPRESSIONS_YAML)
BY = {s["id"]: s for s in SUPS}


def run(today=TODAY):
    return f.triage(f.FINDINGS, SUPS, today)


def test_valid_suppression_hides_the_test_fixture_finding():
    r = run()
    assert [x["rule"] for x in r["suppressed"]] == ["generic-secret"]


def test_real_critical_secret_stays_active():
    assert any(x["rule"] == "aws-access-key-id" for x in run()["active"])


def test_expired_suppression_reactivates_finding_and_says_so():
    r = run()
    assert any(x["rule"] == "subprocess-shell-true" for x in r["active"])
    assert any("SUP-2 expired" in n for n in r["notes"])


def test_before_expiry_the_same_suppression_works():
    r = run(date(2026, 5, 1))
    assert any(x["rule"] == "subprocess-shell-true" and x["suppressed_by"] == "SUP-2" for x in r["suppressed"])


def test_missing_justification_makes_suppression_invalid():
    assert "missing justification" in f.validate_suppression(BY["SUP-4"], TODAY)
    r = run()
    assert any(x["rule"] == "md5-usage" for x in r["active"]) and any("SUP-4 ignored" in n for n in r["notes"])


def test_wildcard_suppression_rejected():
    assert any("too broad" in p for p in f.validate_suppression(BY["SUP-3"], TODAY))


def test_expiry_too_far_rejected():
    assert any("expiry more than" in p for p in f.validate_suppression(BY["SUP-3"], TODAY))


def test_fingerprint_is_stable_and_specific():
    a, b = f.FINDINGS[0], f.FINDINGS[1]
    assert f.fingerprint(a) == f.fingerprint(dict(a)) and f.fingerprint(a) != f.fingerprint(b)


def test_metrics_report_fp_rate():
    m = f.metrics(run())
    assert m == {"total": 5, "suppressed": 1, "fp_rate": 0.2}
