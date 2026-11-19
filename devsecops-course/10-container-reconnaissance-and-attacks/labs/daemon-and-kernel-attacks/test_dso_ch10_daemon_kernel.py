import json
from pathlib import Path

from aisec_lab import load_lab_module

ha = load_lab_module(__file__, "hostattacks")
FIX = Path(__file__).parent / "fixtures"


def load(n):
    return json.loads((FIX / n).read_text())


def test_unauthenticated_tcp_endpoint_is_critical():
    f = ha.audit_daemon(load("daemon-bad.json"))
    assert f[0][0] == "CRITICAL" and "NO TLS" in f[0][1] and "every network interface" in f[0][1]


def test_good_daemon_has_no_findings():
    assert ha.audit_daemon(load("daemon-good.json")) == []


def test_unix_socket_only_is_not_a_tcp_finding():
    f = ha.audit_daemon({"hosts": ["unix:///var/run/docker.sock"], "userns-remap": "default", "icc": False,
                         "no-new-privileges": True, "live-restore": True, "userland-proxy": False})
    assert f == []


def test_tls_on_2375_is_flagged_as_confusing():
    cfg = dict(load("daemon-good.json"), hosts=["tcp://10.0.0.1:2375"])
    assert any("2376" in m for _, m in ha.audit_daemon(cfg))


def test_flat_network_counts_pairs():
    f = ha.flat_network_exposure(load("containers.json"))
    assert len(f) == 1 and "3 reachable pairs" in f[0]


def test_dos_exposure_lists_missing_limits():
    f = " | ".join(ha.dos_exposure(load("containers.json")))
    assert "api: no memory/pids/cpus" in f and "db: no pids" in f
    assert "web:" not in f and "worker:" not in f


def test_fork_growth_with_and_without_limit():
    free = ha.fork_growth(None)
    capped = ha.fork_growth(200)
    assert free["final_processes"] == 32768 and "HOST" in free["hit"]
    assert capped["final_processes"] == 200 and capped["host_impact"].startswith("none")
    assert capped["generations_to_cap"] < free["generations_to_cap"]


def test_kernel_risk_by_version():
    ids = lambda k: {c["id"] for c in ha.kernel_risk(k)}
    assert ids("5.4.0-150") == {"FIXTURE-K-001", "FIXTURE-K-003"}
    assert ids("5.15.0-fixture") == {"FIXTURE-K-001", "FIXTURE-K-002", "FIXTURE-K-003"}
    assert ids("6.8.12") == set()
    assert ids("6.5.1") == {"FIXTURE-K-004"}


def test_kernel_matches_carry_requirements():
    for c in ha.kernel_risk("5.15.0"):
        assert c["needs"] and c["type"]
