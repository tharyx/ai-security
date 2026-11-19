from pathlib import Path

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "breakout")
FIX = Path(__file__).resolve().parent / "fixtures"
SYSTEM = b.load(FIX / "system.json")
KEY = b.load(FIX / "answer_key.json")
TEAM_A = b.check(b.load(FIX / "submissions" / "team_a.json"), KEY, SYSTEM)
TEAM_B = b.check(b.load(FIX / "submissions" / "team_b.json"), KEY, SYSTEM)


def test_system_fixture_is_consistent():
    assert b.validate_system(SYSTEM) == []
    broken = {"zones": {"a": 0}, "elements": [{"id": "x", "type": "process", "zone": "b"}],
              "flows": [{"id": "F1", "src": "x", "dst": "ghost"}]}
    assert len(b.validate_system(broken)) == 2


def test_trust_boundary_crossings_include_both_directions():
    crossings = {c["flow"]: c for c in b.boundary_crossings(SYSTEM)}
    assert set(crossings) == {"F1", "F2", "F3", "F6", "F7", "F8", "F9", "F10"}
    assert crossings["F1"]["inbound"] is True and crossings["F10"]["inbound"] is False
    assert "F4" not in crossings and "F5" not in crossings  # queue traffic stays inside the app zone


def test_attack_surface_is_only_what_outsiders_reach_directly():
    surface = b.attack_surface(SYSTEM)
    assert len(surface) == 3
    assert any(s.startswith("web via F1") for s in surface)
    assert any("payment webhook" in s for s in surface)


def test_web_only_team_fails_and_misses_the_queue_and_webhook():
    assert not TEAM_A.passed
    missing = " ".join(TEAM_A.missing_must)
    assert "queue/T" in missing and "payment_provider/S" in missing and "api/E" in missing
    assert TEAM_A.coverage < 0.3


def test_bad_submissions_are_reported_not_silently_counted():
    errs = " ".join(TEAM_A.errors)
    assert "UNKNOWN_ELEMENT" in errs and "INVALID_STRIDE_LETTER" in errs and "NO_MITIGATION" in errs


def test_full_team_passes_with_all_must_threats():
    assert TEAM_B.passed and TEAM_B.missing_must == [] and TEAM_B.coverage >= 0.8


def test_stride_per_element_warnings_and_log_store_repudiation():
    assert b.typical_letters(SYSTEM, "audit_log") == set("TIDR")
    assert b.typical_letters(SYSTEM, "db") == set("TID")
    sub = {"team": "t", "threats": [{"element": "db", "stride": "S", "text": "x", "mitigation": "y"}]}
    assert b.check(sub, KEY, SYSTEM).warnings


def test_render_shows_verdict_and_sections():
    text = b.render(TEAM_A)
    assert "FAIL" in text and "Missing MUST threats" in text
    assert "PASS" in b.render(TEAM_B)
