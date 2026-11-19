from pathlib import Path

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "detector")
FIX = Path(__file__).resolve().parent / "fixtures"
PROCS, FLOWS = d.load(FIX / "process_events.json"), d.load(FIX / "network_flows.json")
EGRESS = ["10.0.0.0/8"]
ALERTS = {a["pid"]: a for a in d.detect(PROCS, FLOWS, EGRESS)}


def test_shell_with_socket_fds_spawned_by_web_app_is_critical():
    a = ALERTS[300]
    assert a["severity"] == "CRITICAL"
    assert {r[:2] for r in a["rules"]} == {"R1", "R2", "R3"}


def test_dev_tcp_indicator_from_java_service_is_critical():
    assert {r[:2] for r in ALERTS[401]["rules"]} == {"R1", "R3", "R4"}


def test_netcat_with_exec_flag_and_external_egress_is_flagged():
    assert ALERTS[500]["severity"] == "CRITICAL"


def test_benign_cron_shell_is_not_flagged():
    assert 201 not in ALERTS and 200 not in ALERTS


def test_interpreter_child_of_app_with_internal_egress_is_only_medium():
    assert ALERTS[600]["severity"] == "MEDIUM" and len(ALERTS[600]["rules"]) == 1


def test_default_deny_egress_drops_every_attacker_connection():
    blocked = {f["dst"] for f in d.egress_blocked(FLOWS, EGRESS)}
    assert blocked == {"203.0.113.50", "203.0.113.77", "198.51.100.23"}


def test_distroless_nonroot_image_is_clean_and_debian_image_is_not():
    debian, distroless = d.load(FIX / "images.json")
    assert len(d.image_findings(debian)) == 4
    assert d.image_findings(distroless) == []


def test_fixtures_contain_no_working_commands():
    text = (FIX / "process_events.json").read_text()
    assert "[REDACTED" in text and ">&" not in text
