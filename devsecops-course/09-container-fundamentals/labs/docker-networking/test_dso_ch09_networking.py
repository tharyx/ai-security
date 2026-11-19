from pathlib import Path

import pytest
from aisec_lab import load_lab_module

ns = load_lab_module(__file__, "netsim")
T = ns.Topology.load(str(Path(__file__).parent / "fixtures" / "topology.json"))


def test_user_defined_bridge_allows_by_name():
    ok, why = T.can_reach("web", "api", 3000)
    assert ok and "by name" in why


def test_web_cannot_reach_db_different_networks():
    ok, why = T.can_reach("web", "db", 5432)
    assert not ok and "isolated" in why


def test_api_bridges_frontend_and_backend():
    assert T.can_reach("api", "db", 5432)[0]


def test_default_bridge_is_ip_only():
    ok, why = T.can_reach("legacy1", "legacy2", 9000)
    assert ok and "IP only" in why


def test_none_network_is_isolated_both_ways():
    assert not T.can_reach("batch", "web", 80)[0]
    assert not T.can_reach("web", "batch")[0]


def test_overlay_crosses_nodes():
    assert "overlay" in T.can_reach("worker-a", "worker-b", 7001)[1]


def test_host_network_reaches_host_localhost():
    assert 2375 in T.host_localhost_reachable("monitor")
    assert T.host_localhost_reachable("web") == []


def test_publish_parsing_and_scope():
    assert ns.parse_publish("8080:80").exposed_to_network
    assert not ns.parse_publish("127.0.0.1:3000:3000").exposed_to_network
    with pytest.raises(ValueError):
        ns.parse_publish("80")


def test_findings_flag_all_interfaces_and_flat_bridge():
    text = " ".join(T.findings())
    assert "web listens on 0.0.0.0:8080->80" in text
    assert "monitor" in text and "legacy1" in text
    assert "api listens" not in text
