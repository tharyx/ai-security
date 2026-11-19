from pathlib import Path

from aisec_lab import load_lab_module

ev = load_lab_module(__file__, "events")
FIX = Path(__file__).parent / "fixtures"
EVENTS = ev.parse((FIX / "events.jsonl").read_text().splitlines())
ALERTS = ev.detect(EVENTS)
RULES = {a["rule"] for a in ALERTS}


def test_events_sorted_by_time():
    t = [e["time"] for e in EVENTS]
    assert t == sorted(t) and len(EVENTS) == 12


def test_privileged_and_socket_create_are_critical():
    crit = {a["rule"] for a in ALERTS if a["severity"] == "CRITICAL"}
    assert crit == {"EVT-PRIV", "EVT-SOCK"}
    assert ALERTS[0]["severity"] == "CRITICAL"


def test_unapproved_registry_pull_flagged_but_approved_not():
    pulls = [a for a in ALERTS if a["rule"] == "EVT-PULL"]
    assert len(pulls) == 1 and "evil.example.invalid" in pulls[0]["message"]


def test_exec_oom_tag_daemon_reload_detected():
    assert {"EVT-EXEC", "EVT-OOM", "EVT-TAG", "EVT-DAEMON", "EVT-HOSTROOT"} <= RULES


def test_crash_loop_needs_three_failures():
    assert "EVT-CRASHLOOP" in RULES
    two = [e for e in EVENTS if not (e["actor"].get("name") == "worker" and e["time"] == 1700000260)]
    assert "EVT-CRASHLOOP" not in {a["rule"] for a in ev.detect(two)}


def test_clean_stream_has_no_alerts():
    clean = [e for e in EVENTS if e["actor"].get("name") == "shop-web" and e["Action"] in ("create", "start")]
    assert ev.detect(clean) == []


def test_timeline_format():
    tl = ev.timeline(EVENTS)
    assert tl[0].startswith("22:13:20 image.pull")


def test_log_scan_patterns():
    found = ev.scan_logs((FIX / "app.log").read_text().splitlines())
    assert len(found) == 4
    assert any("auth failures" in f for f in found) and any("encoded payload" in f for f in found)
