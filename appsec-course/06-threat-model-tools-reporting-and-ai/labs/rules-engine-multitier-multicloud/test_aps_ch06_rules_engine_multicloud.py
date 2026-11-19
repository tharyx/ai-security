from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ir = load_lab_module(__file__, "iriuslite")
FIX = Path(__file__).resolve().parent / "fixtures"
LIB = ir.load(FIX / "library.json")


def build(name, with_states=True):
    p = ir.load(FIX / name)
    threats = ir.generate(ir.apply_questionnaire(p["components"], p["answers"]), LIB)
    if with_states:
        ir.set_states(threats, p["states"])
    return threats


def by_id(threats):
    return {t.id: t for t in threats}


def test_questionnaire_answers_decide_which_threats_appear():
    p = ir.load(FIX / "multitier.json")
    without = ir.generate(ir.apply_questionnaire(p["components"], {}), LIB)
    with_answers = build("multitier.json", with_states=False)
    assert "WEB-XSS@Storefront" not in by_id(without) and "WEB-XSS@Storefront" in by_id(with_answers)
    assert len(with_answers) == 6


def test_unimplemented_owner_check_leaves_bola_residual_high_and_fails_gate():
    t = by_id(build("multitier.json"))["API-BOLA@Orders API"]
    assert t.residual == 18.0  # only the 10% defense-in-depth control is implemented
    assert ir.gate(build("multitier.json")) == 1


def test_implementing_the_required_countermeasure_lowers_residual_risk():
    threats = build("multitier.json")
    ir.set_states(threats, {"CM-OWNER@Orders API": "Implemented", "CM-MQAUTH@Order events": "Implemented"})
    assert by_id(threats)["API-BOLA@Orders API"].residual == 2.0
    assert ir.gate(threats) == 0


def test_rejected_countermeasure_keeps_full_inherent_risk():
    assert by_id(build("multitier.json"))["MQ-AUTH@Order events"].residual == 12


def test_one_cloud_threat_maps_to_provider_specific_controls():
    threats = by_id(build("multicloud.json"))
    names = {cid.split("@")[1]: threats[cid].countermeasures[0].name for cid in threats if cid.startswith("OBJ-PUBLIC")}
    assert names["Raw uploads (AWS)"].startswith("S3 Block Public Access")
    assert "allowBlobPublicAccess" in names["Curated data (Azure)"]
    assert names["Archive (Google Cloud)"].startswith("Public access prevention")


def test_static_keys_between_clouds_need_workload_identity_federation():
    r = ir.report(build("multicloud.json"))
    assert any(x.startswith("CM-WIF@AWS to Azure copy job") for x in r["required_not_implemented"])
    assert any(x.startswith("CM-NOPUBLIC@Curated data (Azure)") for x in r["required_not_implemented"])


def test_bad_inputs_are_rejected():
    with pytest.raises(KeyError):
        ir.apply_questionnaire([{"name": "a", "type": "web-app"}], {"b": {}})
    with pytest.raises(ValueError):
        ir.set_states(build("multitier.json"), {"CM-ENC@Storefront": "Done-ish"})
