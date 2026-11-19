"""Tests for the tiny Gherkin runner, the simulated app and the security feature files."""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

S = load_lab_module(__file__, "security_steps")
G = S.bdd            # the gherkin_lite module used by the steps
A = S.appmod         # the sim_app module
FEATURES = Path(__file__).parent / "features"
FILES = sorted(FEATURES.glob("*.feature"))


def run(text, vulnerable=False):
    return G.run_text(text, S.steps, S.make_context(vulnerable))


def run_file(path, vulnerable=False):
    return run(path.read_text(encoding="utf-8"), vulnerable)


# ---- parser


def test_parse_feature_tags_background_and_scenarios():
    f = G.parse((FEATURES / "session.feature").read_text(encoding="utf-8"))
    assert f.name == "Session management"
    assert f.tags == ["@session"]
    assert f.background == [("Given", "the application is running")]
    assert len(f.scenarios) == 4


def test_description_lines_are_ignored():
    f = G.parse("Feature: X\n  some free text here\n  Scenario: a\n    Given the application is running\n")
    assert len(f.scenarios) == 1


def test_outline_expands_one_scenario_per_row():
    f = G.parse((FEATURES / "authentication.feature").read_text(encoding="utf-8"))
    names = [s.name for s in f.scenarios if s.name.startswith("Admin area")]
    assert len(names) == 2
    row = [s for s in f.scenarios if s.outline_row][0]
    assert any('"alice"' in t for _, t in row.steps)
    assert not any("<" in t for _, t in row.steps)


def test_parse_errors():
    with pytest.raises(G.GherkinError):
        G.parse("Scenario: no feature\n  Given x\n")
    with pytest.raises(G.GherkinError):
        G.parse("Feature: f\n  Scenario: empty\n")
    with pytest.raises(G.GherkinError):
        G.parse("Feature: f\n  Scenario Outline: o\n    Given <x>\n")   # no Examples
    with pytest.raises(G.GherkinError):
        G.parse("Feature: f\n  Scenario: s\n    Given a\n    Examples:\n      | a |\n")
    with pytest.raises(G.GherkinError):
        G.parse("Feature: f\n  Scenario: s\n    Given a\n    Whatever this is\n")


# ---- runner mechanics


def test_undefined_step_is_reported_and_rest_skipped():
    res = run("Feature: f\n  Scenario: s\n    Given the application is running\n    When something unknown\n"
              "    Then the response status is 200\n")
    sc = res.scenarios[0]
    assert sc.status == "undefined"
    assert [s.status for s in sc.steps] == ["passed", "undefined", "skipped"]


def test_failed_step_stops_the_scenario():
    res = run("Feature: f\n  Scenario: s\n    Given the application is running\n"
              "    When I request \"/\" anonymously\n    Then the response status is 500\n"
              "    And the response status is 200\n")
    sc = res.scenarios[0]
    assert sc.status == "failed"
    assert [s.status for s in sc.steps][-2:] == ["failed", "skipped"]
    assert "expected status 500" in sc.steps[2].error


def test_each_scenario_gets_a_fresh_context():
    text = ("Feature: f\n  Background:\n    Given the application is running\n"
            "  Scenario: a\n    When I fail to log in as \"alice\" 5 times in a row\n    And I log in as \"alice\" with password \"correct-horse\"\n    Then the response status is 423\n"
            "  Scenario: b\n    When I log in as \"alice\" with password \"correct-horse\"\n    Then the response status is 200\n")
    assert run(text).passed


def test_registry_uses_full_match():
    reg = G.StepRegistry()
    reg.step(r"I have (\d+) apples")(lambda ctx, n: None)
    assert reg.find("I have 3 apples")[1] == ("3",)
    assert reg.find("I have 3 apples today")[0] is None


# ---- the app itself


def test_good_app_sets_cookie_flags():
    app = A.SimApp()
    r = app.handle("POST", "/login", {"username": "alice", "password": "correct-horse"})
    c = r.cookie("session")
    assert {"httponly", "secure"} <= c["flags"] and c["attrs"]["samesite"] == "Lax"
    assert len(c["value"]) == 32


def test_good_app_locks_after_threshold_even_for_right_password():
    app = A.SimApp(lockout_threshold=3)
    for _ in range(3):
        app.handle("POST", "/login", {"username": "alice", "password": "bad"})
    assert app.handle("POST", "/login", {"username": "alice", "password": "correct-horse"}).status == 423


def test_vulnerable_app_has_predictable_sessions_and_no_flags():
    app = A.SimApp(vulnerable=True)
    r1 = app.handle("POST", "/login", {"username": "alice", "password": "correct-horse"})
    r2 = app.handle("POST", "/login", {"username": "alice", "password": "correct-horse"})
    assert r1.cookie("session")["value"] == "sess-0001" and r2.cookie("session")["value"] == "sess-0002"
    assert r1.cookie("session")["flags"] == set()


def test_response_header_lookup_is_case_insensitive():
    r = A.SimApp().handle("GET", "/")
    assert r.header("x-frame-options") == "DENY"


# ---- the real point: security requirements as executable specs


def test_there_are_three_feature_files():
    assert [p.name for p in FILES] == ["authentication.feature", "session.feature", "transport_and_exposure.feature"]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_hardened_app_passes_every_scenario(path):
    res = run_file(path)
    assert res.passed, [(s.name, [x.error for x in s.steps if x.error]) for s in res.failed()]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_vulnerable_app_fails_most_scenarios(path):
    res = run_file(path, vulnerable=True)
    assert len(res.failed()) >= 2
    assert not any(s.status == "undefined" for s in res.scenarios)   # failures, not missing steps


def test_named_requirements_fail_for_the_right_reason():
    sess = run_file(FEATURES / "session.feature", vulnerable=True)
    by = {s.name: s for s in sess.scenarios}
    httponly = by["Session cookie must be HttpOnly"]
    assert httponly.status == "failed"
    assert "missing the HttpOnly flag" in [x for x in httponly.steps if x.error][0].error
    login = run_file(FEATURES / "authentication.feature", vulnerable=True)
    lock = {s.name: s for s in login.scenarios}["Login must lock after 5 failures"]
    assert lock.status == "failed"
    assert "got 200" in [x for x in lock.steps if x.error][0].error


def test_user_enumeration_scenario_catches_different_messages():
    login = run_file(FEATURES / "authentication.feature", vulnerable=True)
    sc = {s.name: s for s in login.scenarios}["Error message must not reveal whether the user exists"]
    assert "user enumeration" in [x for x in sc.steps if x.error][0].error


def test_boundary_four_failures_still_allowed_for_both_apps():
    for vuln in (False, True):
        sc = {s.name: s for s in run_file(FEATURES / "authentication.feature", vuln).scenarios}
        assert sc["Four failures do not lock the account yet"].status == "passed"


def test_tags_are_carried_to_results():
    res = run_file(FEATURES / "session.feature")
    assert res.scenarios[0].tags == ["@session"]
