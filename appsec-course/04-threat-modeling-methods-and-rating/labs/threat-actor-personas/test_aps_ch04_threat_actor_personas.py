from pathlib import Path

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "personas")
FIX = Path(__file__).resolve().parent / "fixtures"
TECH = {k: v for k, v in p.load(FIX / "attack_techniques.json").items() if not k.startswith("_")}
PERSONAS = p.load(FIX / "personas.json")["personas"]
THREATS = p.load(FIX / "threats.json")["threats"]
BY_NAME = {x["name"]: x for x in PERSONAS}


def test_all_fixture_personas_are_well_formed():
    assert all(p.validate_persona(x, TECH) == [] for x in PERSONAS)


def test_vague_persona_with_made_up_technique_is_rejected():
    errs = p.validate_persona({"name": "Hackers", "skill": 9, "techniques": ["T9999"]}, TECH)
    assert "MISSING_MOTIVATION" in errs and "SKILL_OUT_OF_RANGE" in errs and "UNKNOWN_TECHNIQUE T9999" in errs


def test_tactics_grouping_handles_multi_tactic_techniques():
    tactics = p.tactics_for(BY_NAME["Ransomware affiliate"], TECH)
    assert "T1078" in tactics["Persistence"] and "T1078" in tactics["Initial Access"]
    assert tactics["Impact"] == ["T1486"]


def test_low_skill_opportunist_only_attempts_low_skill_threats():
    assert p.relevant_threats(BY_NAME["Opportunist with off-the-shelf tools"], THREATS) == ["TH1", "TH6"]


def test_fraud_crew_and_insider_threats():
    assert p.relevant_threats(BY_NAME["Organised fraud crew"], THREATS) == ["TH1", "TH2", "TH3"]
    assert p.relevant_threats(BY_NAME["Disgruntled support insider"], THREATS) == ["TH4"]


def test_business_logic_threat_has_no_attack_mapping():
    assert p.unmapped_threats(THREATS) == ["TH7"]


def test_supply_chain_threat_has_no_matching_persona():
    assert p.uncovered_threats(PERSONAS, THREATS) == ["TH8"]
    nation = {"name": "Well-funded state actor", "motivation": "Espionage", "skill": 5, "resources": "High",
              "access": ["external"], "goals": ["Long-term access"], "techniques": ["T1195", "T1078"]}
    assert p.uncovered_threats(PERSONAS + [nation], THREATS) == []


def test_persona_card_lists_techniques_with_names():
    text = p.card(BY_NAME["Organised fraud crew"], TECH)
    assert text.startswith("### Organised fraud crew") and "T1566 Phishing (Initial Access)" in text
