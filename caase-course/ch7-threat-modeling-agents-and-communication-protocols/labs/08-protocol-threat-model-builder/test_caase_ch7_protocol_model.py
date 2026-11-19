from __future__ import annotations

import copy
from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "validator")
HERE = Path(__file__).resolve().parent


def example() -> dict:
    return v.load(HERE / "example_completed_model.yaml")


def test_completed_example_passes_including_real_test_references():
    assert v.validate(example(), check_test_refs=True) == []


def test_template_fails_with_todos_and_missing_pieces():
    probs = v.validate(v.load(HERE / "protocol_threat_model_template.yaml"))
    assert len(probs) > 10
    assert any("TODO" in p for p in probs)
    assert any("attack class" in p for p in probs)


def test_every_attack_class_is_covered_and_matrix_has_cross_protocol_row():
    m = v.coverage_matrix(example())
    assert all(m[c] for c in v.ATTACK_CLASSES)
    assert "mcp" in m["cross_protocol_confusion"]


def test_removing_a_threat_class_is_reported():
    m = example()
    for block in m["protocol_models"].values():
        block["threats"] = [t for t in block["threats"] if t["attack_class"] != "capability_discovery_abuse"]
    assert any("capability_discovery_abuse" in p for p in v.validate(m))


def test_residual_risk_higher_than_inherent_is_reported():
    m = copy.deepcopy(example())
    m["protocol_models"]["a2a"]["threats"][0]["residual"] = {"likelihood": 5, "impact": 5}
    assert any("residual risk is higher" in p for p in v.validate(m))


def test_high_risk_threat_needs_a_hard_control():
    m = copy.deepcopy(example())
    m["controls"] = [dict(c, type="process", test="manual: review") if c["id"] == "C-12" else c for c in m["controls"]]
    m["protocol_models"]["mcp"]["threats"][0]["controls"] = ["C-12"]  # TH-10 inherent 20, only a process control now
    assert any("needs at least one hard control" in p for p in v.validate(m))


def test_unknown_and_orphan_controls_are_reported():
    m = copy.deepcopy(example())
    m["protocol_models"]["a2a"]["threats"][0]["controls"].append("C-99")
    m["controls"].append({"id": "C-50", "title": "x", "type": "soft", "layer": "x", "test": "manual: x"})
    probs = v.validate(m)
    assert any("unknown control C-99" in p for p in probs)
    assert any("C-50" in p and "not used" in p for p in probs)


def test_hard_control_needs_a_test_reference_and_it_must_exist():
    m = copy.deepcopy(example())
    m["controls"][0]["test"] = "manual: trust me"
    assert any("must point at a test" in p for p in v.validate(m))
    m = copy.deepcopy(example())
    m["controls"][0]["test"] = "03-a2a-spoofing-hijack/test_caase_ch7_a2a_hijack.py::test_does_not_exist"
    assert any("not found" in p for p in v.validate(m, check_test_refs=True))


def test_bad_enums_are_reported():
    m = copy.deepcopy(example())
    t = m["protocol_models"]["ucp_style"]["threats"][0]
    t.update(stride="X", asi="ASI11", attack_class="magic")
    probs = v.validate(m)
    assert sum(("stride" in p or "asi" in p or "attack_class" in p) for p in probs) >= 3


def test_missing_protocol_area_is_reported():
    m = copy.deepcopy(example())
    del m["protocol_models"]["mcp"]
    assert any("mcp: missing" in p for p in v.validate(m))
