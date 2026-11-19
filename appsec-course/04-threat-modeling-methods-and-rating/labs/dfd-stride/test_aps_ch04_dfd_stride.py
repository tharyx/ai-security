from pathlib import Path

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "dfd")
FIX = Path(__file__).resolve().parent / "fixtures"
GOOD = d.load(FIX / "password_reset_dfd.json")
BROKEN = d.load(FIX / "broken_dfd.json")


def test_password_reset_dfd_is_valid():
    assert d.validate(GOOD) == []


def test_validator_catches_every_classic_drawing_mistake():
    errs = " ".join(d.validate(BROKEN))
    for code in ("EXTERNAL_TO_STORE", "STORE_TO_STORE", "MIRACLE", "EXTERNAL_TO_EXTERNAL", "BLACK_HOLE", "DANGLING_FLOW"):
        assert code in errs, code


def test_stride_per_element_letters_by_type():
    threats = d.stride_per_element(GOOD)
    letters = lambda target: "".join(t.letter for t in threats if t.target == target)  # noqa: E731
    assert letters("user") == "SR"
    assert letters("reset_app") == "STRIDE"
    assert letters("users_db") == "TID"
    assert letters("audit_log") == "TIDR"  # log stores also face repudiation
    assert letters("F1") == "TID"


def test_threat_count_is_predictable():
    # 2 externals x2 + 1 process x6 + 2 stores x3 + 1 log store x4 + 8 flows x3
    assert len(d.stride_per_element(GOOD)) == 4 + 6 + 6 + 4 + 24


def test_boundary_crossing_flows_are_prioritised():
    assert d.crossings(GOOD) == ["F1", "F3", "F4", "F6", "F7", "F8"]
    assert {t.priority for t in d.stride_per_element(GOOD) if t.target == "F2"} == {"normal"}
    prios = {t.priority for t in d.stride_per_element(GOOD) if t.target == "F1"}
    assert prios == {"boundary"}


def test_questions_name_the_element_and_property_map_is_complete():
    t = next(t for t in d.stride_per_element(GOOD) if t.target == "reset_app" and t.letter == "S")
    assert "Reset service" in t.question and t.category == "Spoofing"
    assert set(d.PROPERTY) == set(d.STRIDE)


def test_mermaid_has_zones_shapes_and_dashed_boundary_flows():
    m = d.mermaid(GOOD)
    assert m.startswith("flowchart LR")
    assert 'subgraph data["Trust zone: data"]' in m
    assert 'users_db[("Users DB")]' in m and 'reset_app(("Reset service"))' in m
    assert "user -.->|" in m
