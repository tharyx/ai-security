from pathlib import Path

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "privacy")
FIX = Path(__file__).resolve().parent / "fixtures"
V1 = p.load(FIX / "fitness_app_v1.json")
V2 = p.load(FIX / "fitness_app_v2.json")


def cats(system):
    return {(t.category, t.target) for t in p.linddun(system)}


def test_shared_device_id_lets_third_parties_link_profiles():
    assert ("Linking", "device_id") in cats(V1)


def test_email_in_analytics_and_logs_is_identifying():
    found = cats(V1)
    assert ("Identifying", "app to analytics") in found and ("Identifying", "API to logs") in found


def test_account_existence_leak_is_a_detecting_threat():
    assert ("Detecting", "signup/reset") in cats(V1)


def test_data_without_purpose_or_retention_and_cleartext_logs_are_disclosure_threats():
    texts = [t.text for t in p.linddun(V1) if t.category == "Data disclosure"]
    assert "collected without a stated purpose (minimisation)" in texts
    assert "no retention period: kept forever" in texts
    assert "personal data sent without encryption" in texts


def test_missing_rights_and_records_are_unawareness_and_non_compliance():
    found = cats(V1)
    assert ("Unawareness", "user") in found
    assert ("Non-compliance", "app to analytics") in found  # transfer abroad without safeguards
    assert ("Non-compliance", "organisation") in found


def test_dpia_screening_counts_criteria():
    s = p.dpia_screening(V1)
    assert s["required"] and len(s["criteria_met"]) == 4
    assert not p.dpia_screening({"processing": {"large_scale": True}})["required"]


def test_unwanted_non_repudiation_rule():
    system = {"data": [], "flows": [], "features": {"signed_activity_log_of_sensitive_actions": True,
                                                     "privacy_notice": True, "consent_records": True,
                                                     "access_and_deletion_requests": True,
                                                     "record_of_processing": True}}
    assert [t.category for t in p.linddun(system)] == ["Non-repudiation"]


def test_privacy_by_design_version_has_no_findings():
    assert p.linddun(V2) == []
    assert p.dpia_screening(V2)["required"]  # still required, and it was done


def test_threats_become_privacy_requirements_in_linddun_order():
    reqs = p.privacy_requirements(p.linddun(V1))
    assert reqs[0].startswith("PRIV-01") and reqs[-1].startswith("PRIV-07")
    assert not any(r.startswith("PRIV-03") for r in reqs)
