import json
from pathlib import Path

from aisec_lab import load_lab_module

da = load_lab_module(__file__, "daemon_audit")
FIX = Path(__file__).parent / "fixtures"
BAD = json.loads((FIX / "daemon_insecure.json").read_text())
GOOD = json.loads((FIX / "daemon_secure.json").read_text())


def ids(findings):
    return {f.rule_id for f in findings}


def test_insecure_config_findings():
    got = ids(da.audit(BAD))
    assert {"DD-001", "DD-002", "DD-003", "DD-004", "DD-005", "DD-008", "DD-009"} <= got


def test_secure_config_is_clean():
    assert da.audit(GOOD) == []


def test_tls_on_2376_is_not_the_plaintext_finding():
    cfg = dict(GOOD)
    assert "DD-002" not in ids(da.audit(cfg)) and "DD-001" not in ids(da.audit(cfg))


def test_tls_requires_verify_and_certs():
    cfg = dict(GOOD)
    del cfg["tlsverify"]
    assert "DD-001" in ids(da.audit(cfg))


def test_unix_socket_only_has_no_tcp_findings():
    cfg = {"hosts": ["unix:///var/run/docker.sock"], "icc": False, "userns-remap": "default", "no-new-privileges": True,
           "live-restore": True, "log-driver": "json-file", "userland-proxy": False}
    assert da.audit(cfg) == []


def test_listener_scan_flags_2375_only_when_public():
    text = (FIX / "listeners.txt").read_text()
    assert [f.severity for f in da.scan_listeners(text)] == ["CRITICAL"]
    assert da.scan_listeners("LISTEN 0 4096 127.0.0.1:2375 0.0.0.0:* users") == []


def test_socket_permissions():
    assert ids(da.socket_findings("0666", "docker")) == {"DD-013"}
    assert da.socket_findings("0660", "docker") == []
    assert ids(da.socket_findings("0660", "users")) == {"DD-014"}


def test_fake_daemon_open_vs_tls():
    assert da.FakeDaemon(BAD).get_version()[0] == 200
    assert da.FakeDaemon(GOOD).get_version()[0] == 0
    assert da.FakeDaemon(GOOD).get_version(tls_client_cert=True)[0] == 200


def test_severity_sort_puts_critical_first():
    assert da.audit(BAD)[0].severity == "CRITICAL"
