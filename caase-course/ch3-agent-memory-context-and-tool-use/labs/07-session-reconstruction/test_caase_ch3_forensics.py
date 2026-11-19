"""Session reconstruction from memory artifacts and a hash-chained tool log."""

import json
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "forensics")


@pytest.fixture
def bad():
    with tempfile.TemporaryDirectory() as d:
        f.simulate_session(d, compromised=True)
        yield d


@pytest.fixture
def good():
    with tempfile.TemporaryDirectory() as d:
        f.simulate_session(d, compromised=False)
        yield d


def test_clean_session_has_no_injection_and_scores_low(good):
    r = f.reconstruct(good)
    assert r.injection_seq is None and r.first_anomaly_seq is None
    assert r.exfiltrated == [] and r.tainted_memory == [] and r.severity == "low"  # one customer read is exposure, not a breach
    assert r.exposed == ["customer-7-record"]


def test_timeline_merges_sources_in_time_order(bad):
    r = f.reconstruct(bad)
    times = [t for t, _, _ in r.timeline]
    assert times == sorted(times)
    assert {kind for _, kind, _ in r.timeline} == {"transcript", "tool", "memory"}


def test_injection_point_is_the_untrusted_ticket_read(bad):
    r = f.reconstruct(bad)
    assert r.injection_seq == 0
    assert r.first_anomaly_seq == 2  # the e-mail to the outside address


def test_blast_radius_and_score(bad):
    r = f.reconstruct(bad)
    assert r.exfiltrated == ["customer-7-record"] and r.exposed == ["customer-7-record"]
    assert r.tainted_memory == ["reply_to (from tool:get_ticket)"]
    assert r.off_policy_calls == [2]
    assert r.score == 85 and r.severity == "critical"


def test_recommended_actions_follow_the_findings(bad):
    acts = " | ".join(f.reconstruct(bad).actions)
    assert "rotate" in acts and "purge memory" in acts and "#0" in acts


def test_the_final_answer_hides_the_attack_so_the_transcript_alone_is_not_enough(bad):
    r = f.reconstruct(bad)
    assert any("Nothing unusual" in line for _, kind, line in r.timeline if kind == "transcript")
    assert r.severity == "critical"  # only the tool log and memory reveal it


def test_log_integrity_is_verified_and_tampering_is_located(bad):
    assert f.reconstruct(bad).log_ok
    p = Path(bad) / "tool_log.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["args"]["to"] = "helpdesk@corp.example"  # attacker rewrites the e-mail entry
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines))
    r = f.reconstruct(bad)
    assert not r.log_ok and r.log_broken_at == 2
    assert any("log was altered" in a for a in r.actions)


def test_deleting_a_log_entry_breaks_the_chain(bad):
    p = Path(bad) / "tool_log.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[0], lines[2]]))
    assert f.reconstruct(bad).log_broken_at == 1


def test_missing_memory_file_is_handled(bad):
    (Path(bad) / "memory.json").unlink()
    r = f.reconstruct(bad)
    assert r.tainted_memory == [] and r.injection_seq == 0
