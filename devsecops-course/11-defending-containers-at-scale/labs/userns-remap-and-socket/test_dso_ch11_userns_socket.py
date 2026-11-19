import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "daemon_checks")
FIX = Path(__file__).parent / "fixtures"
BAD = json.loads((FIX / "daemon_bad.json").read_text())
GOOD = json.loads((FIX / "daemon_good.json").read_text())
SUBUID = (FIX / "subuid").read_text()


def test_userns_missing_is_flagged():
    assert "container root is host root" in d.check_userns(BAD, SUBUID, SUBUID)[0]


def test_userns_ok_and_missing_range():
    assert d.check_userns(GOOD, SUBUID, SUBUID) == []
    out = d.check_userns(GOOD, (FIX / "subuid_missing").read_text(), SUBUID)
    assert len(out) == 1 and "subuid" in out[0]


def test_tcp_without_tls_is_critical_and_good_passes():
    sev = [s for s, _ in d.check_tcp(BAD)]
    assert sev.count("critical") == 2
    assert d.check_tcp(GOOD) == []


def test_tls_without_verify_is_high():
    cfg = {"hosts": ["tcp://10.0.0.5:2376"], "tls": True}
    assert d.check_tcp(cfg)[0][0] == "high"


def test_mutual_tls_on_all_interfaces_is_medium():
    cfg = dict(GOOD, hosts=["tcp://0.0.0.0:2376"])
    assert d.check_tcp(cfg)[0][0] == "medium"


def test_fd_socket_unit_bad_and_good():
    bad = " ".join(d.check_fd(BAD, (FIX / "docker.socket.bad").read_text()))
    assert "0666" in bad and "SocketGroup" not in bad.replace("SocketGroup should", "")
    assert d.check_fd(GOOD, (FIX / "docker.socket.good").read_text()) == []
    assert "does not use fd://" in d.check_fd({"hosts": ["unix:///var/run/docker.sock"]}, "")[0]


def test_client_cert_expiry_and_allowlist():
    cert = json.loads((FIX / "client_cert.json").read_text())
    assert d.check_client_cert(cert, {"ci-runner-01"}, date(2026, 11, 19)) == []
    assert "expired" in d.check_client_cert(cert, {"ci-runner-01"}, date(2028, 1, 1))[0]
    assert "allow list" in d.check_client_cert(cert, {"other"}, date(2026, 11, 19))[0]
    assert d.check_client_cert(dict(cert, eku=["serverAuth"]), {"ci-runner-01"}, date(2026, 11, 19))
