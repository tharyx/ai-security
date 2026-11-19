import copy
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "validate")
FIX = Path(__file__).resolve().parent / "fixtures"
MODEL, INV, RES = v.load(FIX / "model.json"), v.load(FIX / "inventory.json"), v.load(FIX / "test_results.json")
TODAY = date(2026, 11, 19)


def fixed_inputs():
    """The model after the team acted on every validation finding."""
    model = copy.deepcopy(MODEL)
    model["reviewed_version"], model["next_review"] = "2.4.0", "2027-02-01"
    model["components"] = [c for c in model["components"] if c["name"] != "Legacy FTP export"]
    model["components"].append({"name": "Reports Worker"})
    model["flows"] += [{"from": "Reports Worker", "to": "Orders DB", "crosses_boundary": False},
                       {"from": "Reports Worker", "to": "partner-sftp.example.net", "crosses_boundary": True}]
    model["threats"] = [t for t in model["threats"] if t["id"] != "T6"]
    for t in model["threats"]:
        if t["id"] == "T3":
            t["tests"] = ["test_admin_needs_mfa"]
        if t["id"] == "T4":
            t["acceptance"]["approved_by"] = "ciso"
        if t["id"] == "T5":
            t.update(status="mitigated", mitigation="rate limit per client", tests=["test_429_after_limit"])
    model["threats"] += [
        {"id": "T7", "target": "Reports Worker", "stride": "Information Disclosure", "status": "mitigated",
         "mitigation": "read-only DB role", "tests": ["test_reports_role_is_read_only"]},
        {"id": "T8", "target": "Reports Worker -> partner-sftp.example.net", "stride": "Information Disclosure",
         "status": "transferred", "transferred_to": "partner contract clause 7 (fictional)"},
        {"id": "T9", "target": "Web App -> Orders API", "stride": "Spoofing", "status": "mitigated",
         "mitigation": "mutual TLS between services", "tests": ["test_api_rejects_without_client_cert"]}]
    results = dict(RES, test_bola_returns_403="pass", test_admin_needs_mfa="pass", test_429_after_limit="pass",
                   test_reports_role_is_read_only="pass", test_api_rejects_without_client_cert="pass")
    return model, results


def test_reality_shows_shadow_component_stale_component_and_unmodeled_flows():
    problems = v.model_vs_reality(MODEL, INV)
    assert "SHADOW: Reports Worker is deployed but not in the model" in problems
    assert "STALE: Legacy FTP export is in the model but not deployed" in problems
    assert any(p.startswith("UNMODELED FLOW: Reports Worker -> partner-sftp") for p in problems)


def test_open_threat_and_incomplete_acceptance_are_not_decisions():
    problems = v.accounted_for(MODEL, TODAY)
    assert "T5: status 'open' is not a decision" in problems
    assert "T4: accepted without owner, approver and expiry" in problems
    assert "T6: marked mitigated but no mitigation is described" in problems


def test_expired_acceptance_is_reported():
    model = copy.deepcopy(MODEL)
    model["threats"][3]["acceptance"]["approved_by"] = "ciso"
    assert "T4: risk acceptance expired on 2027-06-30" in v.accounted_for(model, date(2027, 7, 1))


def test_boundary_flow_without_threats_is_reported():
    problems = v.accounted_for(MODEL, TODAY)
    assert "Web App -> Orders API: boundary-crossing flow has no threats" in problems
    assert not any(p.startswith("Orders API -> Orders DB") for p in problems)  # internal flow


def test_mitigation_with_failing_or_missing_test_is_not_proven():
    problems = v.mitigations_tested(MODEL, RES)
    assert "T2: test test_bola_returns_403 FAILED, so the mitigation is not proven" in problems
    assert "T3: mitigation 'MFA for admins' has no test" in problems
    assert not any(p.startswith("T1") for p in problems)


def test_not_done_until_every_exit_criterion_holds():
    done = v.are_we_done(MODEL, INV, RES, TODAY)
    assert not any(done.values()) and v.gate(done) == 1


def test_fixed_model_passes_all_exit_criteria():
    model, results = fixed_inputs()
    done = v.are_we_done(model, INV, results, TODAY)
    assert all(done.values()), done
    assert v.gate(done) == 0
