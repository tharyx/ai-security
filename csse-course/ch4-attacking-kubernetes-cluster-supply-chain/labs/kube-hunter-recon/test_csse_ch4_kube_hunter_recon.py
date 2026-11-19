from pathlib import Path

from aisec_lab import load_lab_module

recon = load_lab_module(__file__, "recon")
EP = recon.load(Path(__file__).parent / "fixtures/cluster_endpoints.json")


def by_target(findings):
    out = {}
    for f in findings:
        out.setdefault(f.target, set()).add(f.rule_id)
    return out


def test_hardened_api_server_only_leaks_version():
    got = by_target(recon.analyse(EP))
    assert got["203.0.113.10:6443"] == {"REC-002"}


def test_open_api_server_is_critical():
    assert "REC-001" in by_target(recon.analyse(EP))["203.0.113.11:6443"]


def test_kubelet_pods_and_run_are_critical_and_public():
    got = by_target(recon.analyse(EP))["203.0.113.21:10250"]
    assert {"REC-010", "REC-011", "REC-040"} <= got


def test_read_only_port_is_flagged():
    assert "REC-012" in by_target(recon.analyse(EP))["203.0.113.22:10255"]


def test_etcd_without_client_cert():
    assert "REC-020" in by_target(recon.analyse(EP))["203.0.113.30:2379"]


def test_dashboard_without_auth():
    assert "REC-030" in by_target(recon.analyse(EP))["203.0.113.40:8443"]


def test_locked_down_kubelet_has_no_findings():
    assert "203.0.113.23:10250" not in by_target(recon.analyse(EP))


def test_criticals_sort_first():
    assert recon.analyse(EP)[0].severity == "CRITICAL"


def test_report_carries_legacy_banner_and_modern_tools():
    text = recon.report(EP)
    assert text.startswith("kube-hunter is legacy") and "trivy k8s" in text and "Kubescape" in text


def test_inventory_uses_documentation_addresses_only():
    assert all(e["host"].startswith("203.0.113.") for e in EP)
