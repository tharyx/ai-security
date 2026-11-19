import json
from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "audit_host")
FIX = Path(__file__).parent / "fixtures"
BEFORE = json.loads((FIX / "buildserver_before.json").read_text())
AFTER = json.loads((FIX / "buildserver_after.json").read_text())


def test_before_fails_gate_and_after_passes():
    assert a.run(BEFORE)["exit_code"] == 1
    r = a.run(AFTER)
    assert r["exit_code"] == 0 and r["score"] == 100.0


def test_shares_the_cis_auditor():
    assert a.cis.CHECKS and a.cis.__name__ == "dso_ch11_cis_audit_shared"


def test_before_has_the_expected_root_causes():
    f = set(a.run(BEFORE)["failed"])
    assert {"1.2.2", "2.6", "3.16", "5.4", "5.31"} <= f


def test_remediation_text_for_failures_only():
    rem = a.run(BEFORE)["remediation"]
    assert any(x.startswith("5.31") for x in rem)
    assert a.run(AFTER)["remediation"] == []


def test_parse_docker_info():
    d = a.parse_docker_info((FIX / "docker_info.txt").read_text())
    assert d["log-driver"] == "syslog" and d["live-restore"] is True
    assert "userns" in d["security-options"] and "seccomp" in d["security-options"]


def test_cross_check_detects_drift():
    info = {"live-restore": False, "security-options": ["seccomp"]}
    msgs = a.cross_check(AFTER, info)
    assert any("live-restore" in m for m in msgs) and any("userns" in m for m in msgs)
    good = a.parse_docker_info((FIX / "docker_info.txt").read_text())
    assert a.cross_check(AFTER, good) == []
