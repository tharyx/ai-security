"""Tests for the log analyzer. Run: python -m pytest cybersecurity-track/01-it-fundamentals"""

from aisec_lab import load_lab_module

la = load_lab_module(__file__, "log_analyzer")
sd = load_lab_module(__file__, "sample_data")


def _all():
    return la.parse_windows_events(sd.WINDOWS_JSON) + la.parse_auth_log(sd.AUTH_LOG)


def test_parse_windows_counts_and_kinds():
    ev = la.parse_windows_events(sd.WINDOWS_JSON)
    kinds = [e.kind for e in ev]
    assert kinds.count("login_failed") == 8
    assert kinds.count("user_created") == 1
    assert kinds.count("service_installed") == 2
    assert ev == sorted(ev, key=lambda e: e.time)


def test_unknown_event_ids_ignored():
    assert la.parse_windows_events([{"TimeCreated": "2026-01-01T00:00:00Z", "EventID": 9999}]) == []


def test_parse_auth_log_extracts_invalid_user_and_ip():
    ev = la.parse_auth_log(sd.AUTH_LOG)
    first = ev[0]
    assert (first.kind, first.user, first.source_ip) == ("login_failed", "admin", "198.51.100.77")
    assert any(e.kind == "user_created" and e.user == "support9" for e in ev)


def test_auth_log_ignores_garbage_lines():
    assert la.parse_auth_log("this is not syslog\n\n") == []


def test_windows_burst_detected_with_success_after():
    f = la.failed_login_bursts(la.parse_windows_events(sd.WINDOWS_JSON))
    assert {x.rule for x in f} == {"failed_login_burst", "success_after_burst"}
    assert all("203.0.113.50" in x.summary for x in f)


def test_linux_burst_detected():
    f = la.failed_login_bursts(la.parse_auth_log(sd.AUTH_LOG))
    assert {x.rule for x in f} == {"failed_login_burst", "success_after_burst"}


def test_two_typos_are_not_a_burst():
    ev = la.parse_windows_events(sd.WINDOWS_JSON)
    bob = [e for e in ev if e.user == "bob"]
    assert la.failed_login_bursts(bob) == []


def test_burst_must_fit_inside_window():
    ev = la.parse_windows_events(sd.WINDOWS_JSON)
    # failures are 3 s apart: only 2 fit in a 5-second window
    assert la.failed_login_bursts(ev, threshold=5, window_seconds=5) == []


def test_new_users_both_platforms():
    names = " ".join(x.summary for x in la.new_users(_all()))
    assert "svc_backup2" in names and "support9" in names


def test_new_service_risky_vs_normal():
    f = la.new_services(la.parse_windows_events(sd.WINDOWS_JSON))
    by_name = {("WinUpdateHelper" if "WinUpdateHelper" in x.summary else "ExampleAgent"): x.severity for x in f}
    assert by_name == {"WinUpdateHelper": "high", "ExampleAgent": "low"}


def test_encoded_powershell():
    f = la.encoded_powershell(la.parse_windows_events(sd.WINDOWS_JSON))
    assert len(f) == 1 and f[0].severity == "high"


def test_analyze_sorted_critical_first():
    f = la.analyze(_all())
    assert f[0].severity == "critical"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranks = [order[x.severity] for x in f]
    assert ranks == sorted(ranks)


def test_clean_input_no_findings():
    ev = la.parse_auth_log("Nov  2 10:30:00 web01 sshd[2300]: Accepted publickey for deploy from 192.0.2.25 port 41000 ssh2")
    assert la.analyze(ev) == []
