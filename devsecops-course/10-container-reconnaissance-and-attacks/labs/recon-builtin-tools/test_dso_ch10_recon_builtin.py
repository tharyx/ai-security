from pathlib import Path

from aisec_lab import load_lab_module

rc = load_lab_module(__file__, "recon")
DATA = rc.load(str(Path(__file__).parent / "fixtures"))
INV = {i.name: i for i in rc.inventory(DATA)}


def test_inventory_covers_all_containers_including_stopped():
    assert set(INV) == {"shop-web", "shop-api", "shop-db", "ops-agent", "old-batch"}
    assert INV["old-batch"].status.startswith("Exited")


def test_ranking_puts_privileged_host_agent_first():
    inv = rc.inventory(DATA)
    assert inv[0].name == "ops-agent" and inv[0].level == "CRITICAL"
    assert "privileged" in inv[0].risks and "host PID namespace" in inv[0].risks


def test_api_has_socket_cap_and_secrets():
    api = INV["shop-api"]
    assert any("docker.sock" in r for r in api.risks)
    assert "cap_add NET_ADMIN" in api.risks
    assert api.secret_env_names == ["DB_PASSWORD", "API_TOKEN"]
    assert "seccomp/apparmor disabled" in api.risks


def test_hardened_web_scores_low():
    assert INV["shop-web"].level == "LOW"
    assert INV["shop-web"].score < 10


def test_secret_file_reference_is_not_a_secret():
    assert INV["shop-db"].secret_env_names == []


def test_published_on_all_interfaces_flagged():
    assert "port published on all interfaces" in INV["shop-web"].risks
    assert "port published on all interfaces" not in INV["shop-api"].risks


def test_host_findings():
    text = " ".join(rc.host_findings(DATA))
    assert "rootful" in text
    assert "insecure registry configured: registry.internal:5000" in text
    assert "unused volumes" in text
    assert "network 'backend'" in text and "network 'bridge'" not in text   # bridge has only one container
