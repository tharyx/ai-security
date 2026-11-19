import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

td = load_lab_module(__file__, "tdmodel")
cx = load_lab_module(__file__, "cairis_explore")
FIX = Path(__file__).resolve().parent / "fixtures"
TD = td.load(FIX / "threat_dragon_shop.json")
CX = cx.load(FIX / "cairis_clinic.xml")


def test_threat_dragon_model_is_parsed_into_elements_and_flows():
    s = td.summary(TD)
    assert (s["elements"], s["flows"], s["threats"]) == (5, 3, 7)


def test_unanalysed_element_and_unexplained_out_of_scope_are_reported():
    problems = td.validate(TD)
    assert "Orders DB: in scope but no threats recorded (not analysed?)" in problems
    assert "CDN: out of scope without a reason" in problems
    assert not any(p.startswith("SQL:") and "out of scope" in p for p in problems)  # has a reason


def test_flag_mismatch_bad_type_and_dangling_flow_are_reported():
    problems = td.validate(TD)
    assert "Orders API: hasOpenThreats flag does not match the threat list" in problems
    assert "Orders API: threat 'Rate limit missing' has non-STRIDE type 'Gremlins'" in problems
    assert "SQL: flow target points to a missing cell" in problems
    assert "Order calls: crosses a public network unencrypted" in problems


def test_open_high_threats_are_listed():
    assert td.open_threats(TD, "High") == [
        ("Web App", "Tampering", "Stored XSS in product reviews"),
        ("Orders API", "Elevation of privilege", "BOLA on /orders/{id}"),
        ("Order calls", "Information disclosure", "Order data sniffed between data centres")]


def test_wrong_version_is_flagged():
    old = copy.deepcopy(TD)
    old["version"] = "1.6.1"
    assert any("expects Threat Dragon 2.x" in p for p in td.validate(old))


def test_cairis_risks_are_scored_and_sorted():
    scores = [(r.name, r.score) for r in cx.risks(CX)]
    assert scores == [("R1 Ransomware via reception PC", 16), ("R2 Snooping on records", 9), ("R3 Scraping", 4)]


def test_cairis_exploration_answers_review_questions():
    assert cx.environments(CX) == ["Day", "Night"]
    assert cx.unprotected_assets(CX) == ["Patient records"]
    assert "Curious insider -> Browsing records without a reason -> Patient records (Night, score 9)" in cx.attacker_paths(CX)
    assert cx.persona_tasks_at_risk(CX) == ["Priya (receptionist): 'Book appointment' uses high-risk ['Reception PC']"]


def test_xml_with_doctype_is_refused():
    with pytest.raises(ValueError):
        cx.safe_parse('<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>')
