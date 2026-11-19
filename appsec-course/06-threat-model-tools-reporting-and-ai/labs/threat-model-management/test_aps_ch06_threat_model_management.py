from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "tm_manage")
THREATS = m.load(Path(__file__).resolve().parent / "fixtures" / "threats.json")
TODAY = date(2026, 11, 19)


def test_naive_export_creates_duplicate_tickets_on_every_run():
    tracker = []
    for _ in range(3):
        tracker = m.naive_sync(THREATS, tracker)
    assert len(tracker) == 6  # 2 open threats x 3 runs, and the 2 are really the same threat


def test_fingerprint_ignores_case_and_punctuation():
    assert m.fingerprint(THREATS[0]) == m.fingerprint(THREATS[1])
    assert len(m.dedupe(THREATS)) == 5
    kept = next(t for t in m.dedupe(THREATS) if t["component"] == "Orders API")
    assert kept["severity"] == "High"


def test_managed_sync_is_idempotent():
    tracker, _ = m.sync(THREATS, {}, TODAY)
    again, notes = m.sync(THREATS, tracker, TODAY)
    assert again == tracker and not any(n.startswith("created") for n in notes)
    assert len(tracker) == 2  # one open threat (deduplicated) + one accepted risk


def test_vulnerability_becomes_bug_and_acceptance_becomes_risk_ticket():
    tracker, _ = m.sync(THREATS, {}, TODAY)
    types = sorted(t["type"] for t in tracker.values())
    assert types == ["Bug", "Risk acceptance"]


def test_closing_a_ticket_without_fixing_the_threat_reopens_it():
    tracker, _ = m.sync(THREATS, {}, TODAY)
    fp = m.fingerprint(THREATS[0])
    tracker[fp]["state"] = "Done"
    tracker, notes = m.sync(THREATS, tracker, TODAY)
    assert tracker[fp]["state"] == "Reopened" and any(n.startswith("REOPENED") for n in notes)


def test_expired_acceptance_is_flagged():
    _, notes = m.sync(THREATS, {}, TODAY)
    assert any(n.startswith("EXPIRED") for n in notes)
    _, notes = m.sync(THREATS, {}, date(2026, 1, 1))
    assert not any(n.startswith("EXPIRED") for n in notes)


def test_mitigation_must_link_to_existing_code_or_test():
    problems = m.check_code_links(THREATS, {"src/auth/mfa.py", "tests/test_mfa.py", "src/rate_limit.py"})
    assert "T4: reference src/ratelimit.py does not exist (renamed or deleted?)" in problems
    assert "T6: mitigated but no code or test reference" in problems
    assert not any(p.startswith("T3") for p in problems)


def test_generated_document_and_gate():
    doc = m.to_markdown("Shop", THREATS)
    assert "Open 1, mitigated 3, accepted 1." in doc and doc.count("| TM-") == 5
    assert m.ci_gate(THREATS, [], []) == 1  # open High BOLA
    fixed = [dict(t, status="mitigated", code_refs=["src/a.py"]) if t["status"] == "open" else t for t in THREATS]
    assert m.ci_gate(fixed, [], []) == 0
