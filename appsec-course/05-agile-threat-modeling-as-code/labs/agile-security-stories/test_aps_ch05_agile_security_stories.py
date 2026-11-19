from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "agile_sec")
FIX = Path(__file__).resolve().parent / "fixtures"
WEAK = a.load(FIX / "backlog_weak.json")
GOOD = a.load(FIX / "backlog_good.json")


def test_user_story_template_is_parsed():
    p = a.parse_story("As a customer, I want to reset my password so that I can log in")
    assert (p.role, p.goal, p.benefit) == ("customer", "to reset my password", "I can log in")
    assert a.parse_story("Make admin page faster") is None


def test_security_relevance_from_tags_and_words():
    assert a.is_security_relevant({"text": "As a user, I want to upload a photo so that x", "tags": []})
    assert not a.is_security_relevant({"text": "As a user, I want a dark theme so that x", "tags": ["ui"]})


def test_weak_backlog_lets_a_risky_story_ship_without_security_criteria():
    problems = a.check_backlog(WEAK)
    assert "US-1: security-relevant story has no SEC: acceptance criterion" in problems
    assert "US-2: security-relevant story has no abuse case (Definition of Ready)" in problems
    assert "US-1: marked done but security tests have not passed (Definition of Done)" in problems
    assert a.gate(WEAK) == 1


def test_abuse_case_must_be_written_as_an_attacker_with_a_mitigation_and_a_test():
    problems = a.check_backlog(WEAK)
    assert "AB-1: abuse case must be written from an attacker's point of view" in problems
    assert "AB-1: abuse case has no mitigating story" in problems
    assert "AB-1: abuse case cannot become a test (needs given/when/then)" in problems


def test_sprint_planning_must_threat_model_security_relevant_stories():
    problems = a.check_backlog(WEAK)
    assert "US-1: pulled into the Sprint without threat modeling at Sprint Planning" in problems
    assert not any(p.startswith("US-3") for p in problems)  # dark theme is not security relevant


def test_good_backlog_passes_the_gate():
    assert a.check_backlog(GOOD) == [] and a.gate(GOOD) == 0


def test_abuse_cases_become_gherkin_scenarios_with_threat_tags():
    g = a.to_gherkin(GOOD)
    assert g.startswith("Feature: Abuse cases from the threat model")
    assert "@threat-AB-2 @information-disclosure" in g
    assert '    When I request the CSV export for customer "alice"' in g
    assert g.count("Scenario:") == 3


def test_scrum_events_follow_the_2020_scrum_guide():
    events = set(a.SCRUM_SECURITY)
    assert {"Sprint", "Sprint Planning", "Daily Scrum", "Sprint Review", "Sprint Retrospective"} <= events
