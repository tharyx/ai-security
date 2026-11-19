import json
import pathlib
import tempfile
from datetime import date

import pytest

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "vetting")
FX = pathlib.Path(__file__).parent / "fixtures"
INTEL = json.loads((FX / "intel.json").read_text())
TODAY = date(2026, 11, 19)


def req(name, version="1.0.0", ctype="open_source", **kw):
    r = dict(name=name, version=version, component_type=ctype, requester="t",
             justification="j", use="runtime")
    r.update(kw)
    return r


def run(name, version="1.0.0", ctype="open_source"):
    return v.vet(req(name, version, ctype), INTEL, TODAY)


def status(dec, check):
    return next(f.status for f in dec.findings if f.check == check)


def test_template_form_loads_and_is_complete():
    r = v.load_request((FX / "request-template.yaml").read_text())
    assert v.check_form(r)[0].status == "pass"


def test_healthy_package_approved():
    d = run("acme-http", "3.2.1")
    assert d.outcome == v.APPROVE and d.score >= 8


def test_copyleft_review_is_conditional():
    d = run("yamlish", "0.9.0")
    assert d.outcome == v.CONDITIONAL and status(d, "license") == "condition"


def test_agpl_rejected():
    d = run("agpl-chart", "5.0.0")
    assert d.outcome == v.REJECT and status(d, "license") == "fail"


def test_typosquat_rejected():
    d = run("reqeusts", "2.0.0")
    assert d.outcome == v.REJECT
    assert "requests" in next(f.detail for f in d.findings if f.check == "malicious_heuristics")


def test_unfixed_critical_rejected():
    d = run("oldcrypto", "1.1.0")
    assert d.outcome == v.REJECT and status(d, "vulnerabilities") == "fail"


def test_fixed_high_vuln_is_conditional_with_upgrade_hint():
    d = run("parsekit", "2.3.1")
    assert d.outcome == v.CONDITIONAL
    assert any("2.3.2" in c for c in d.conditions)


def test_same_package_fixed_version_approved():
    assert run("parsekit", "2.3.2").outcome == v.APPROVE


def test_known_exploited_rejected_even_with_fix_available():
    d = run("exploited-lib", "4.0.0")
    assert d.outcome == v.REJECT and "known-exploited" in next(
        f.detail for f in d.findings if f.check == "vulnerabilities")


def test_single_maintainer_low_score_not_approved():
    d = run("tiny-utils", "1.0.0")
    assert d.outcome in (v.CONDITIONAL, v.REJECT)
    assert status(d, "maintainer_health") == "condition"


def test_unknown_open_source_package_needs_manual_review():
    d = run("never-seen-before")
    assert d.outcome != v.APPROVE and any("manual review" in c for c in d.conditions)  # no license data also fails


def test_missing_form_fields_rejected():
    d = v.vet({"name": "x"}, INTEL, TODAY)
    assert d.outcome == v.REJECT and "missing fields" in d.findings[0].detail


def test_bad_component_type_rejected():
    assert v.vet(req("acme-http", ctype="magic"), INTEL, TODAY).outcome == v.REJECT


def test_commercial_without_sbom_is_conditional():
    d = run("vendorsdk", "8.1", "commercial")
    assert d.outcome == v.CONDITIONAL
    assert any("vendor SBOM" in c for c in d.conditions)


def test_proprietary_with_evidence_approved():
    assert run("internal-billing", "1.7", "proprietary").outcome == v.APPROVE


def test_proprietary_without_evidence_conditional():
    d = v.vet(req("internal-newsvc", "0.1", "proprietary"), {"internal-newsvc": {
        "license": "Apache-2.0", "evidence": {"code_review_enforced": False},
        "maintainers": {"last_release": "2026-10-01", "active_maintainers": 3}}}, TODAY)
    assert d.outcome == v.CONDITIONAL


def test_third_party_needs_contract_clause():
    d = v.vet(req("partner-lib", "1.0", "third_party"), {"partner-lib": {
        "license": "MIT", "maintainers": {"last_release": "2026-10-01", "active_maintainers": 3}}}, TODAY)
    assert d.outcome == v.CONDITIONAL


@pytest.mark.parametrize("scores,expected", [
    ({"Maintained": 10, "Code-Review": 10}, 10.0),
    ({"Maintained": 0, "Code-Review": 10}, 5.0),
    ({"Maintained": -1, "Code-Review": 4}, 4.0),
    ({}, None),
])
def test_scorecard_score(scores, expected):
    assert v.scorecard_score(scores) == expected


def test_audit_record_and_chain():
    with tempfile.TemporaryDirectory() as d:
        log = v.AuditLog(str(pathlib.Path(d) / "a.jsonl"))
        r1 = log.record(run("acme-http", "3.2.1"), TODAY)
        r2 = log.record(run("oldcrypto", "1.1.0"), TODAY)
        assert r1["outcome"] == "approve" and r2["outcome"] == "reject"
        assert r2["prev"] == r1["hash"]
        assert log.verify_chain()


def test_audit_tamper_detected():
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "a.jsonl"
        log = v.AuditLog(str(p))
        log.record(run("oldcrypto", "1.1.0"), TODAY)
        log.record(run("acme-http", "3.2.1"), TODAY)
        p.write_text(p.read_text().replace('"reject"', '"approve"', 1))
        assert not log.verify_chain()


def test_audit_contains_reasons():
    with tempfile.TemporaryDirectory() as d:
        log = v.AuditLog(str(pathlib.Path(d) / "a.jsonl"))
        rec = log.record(run("agpl-chart", "5.0.0"), TODAY, reviewer="alice")
        assert rec["reviewer"] == "alice"
        assert any(f[0] == "license" and f[1] == "fail" for f in rec["findings"])


def test_stale_package_flagged():
    d = v.check_maintainers({"maintainers": {"last_release": "2020-01-01", "active_maintainers": 3}}, TODAY)
    assert d.status == "condition" and "over a year" in d.detail


def test_recent_owner_change_plus_other_issue_fails():
    f = v.check_maintainers({"maintainers": {"last_release": "2026-10-01", "active_maintainers": 1,
                                             "owner_changed_days_ago": 10}}, TODAY)
    assert f.status == "fail"
