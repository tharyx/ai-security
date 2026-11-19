from pathlib import Path

from aisec_lab import load_lab_module

ks = load_lab_module(__file__, "kubelet_sim")
FIX = Path(__file__).parent / "fixtures"
PODS = [{"namespace": "shop", "name": "web-1", "image": "web:1"}]
BAD = ks.load_config((FIX / "kubelet-insecure.yaml").read_text())
GOOD = ks.load_config((FIX / "kubelet-hardened.yaml").read_text())


def test_insecure_kubelet_lists_pods_to_anyone():
    status, body = ks.Kubelet(BAD, PODS).handle("GET", "/pods")
    assert status == 200 and body == ["shop/web-1 (web:1)"]


def test_insecure_kubelet_run_is_simulated_only():
    status, body = ks.Kubelet(BAD, PODS).handle("POST", "/run/shop/web-1/app", body={"cmd": "id"})
    assert status == 200 and "SIMULATED" in body and "nothing was executed" in body


def test_hardened_kubelet_rejects_anonymous():
    assert ks.Kubelet(GOOD, PODS).handle("GET", "/pods")[0] == 401


def test_webhook_authorization_limits_authenticated_users():
    k = ks.Kubelet(GOOD, PODS, allowed={"prometheus": {"nodes/metrics"}})
    assert k.handle("GET", "/metrics", user="prometheus")[0] == 200
    assert k.handle("GET", "/pods", user="prometheus")[0] == 403
    assert k.handle("POST", "/run/shop/web-1/app", user="prometheus", body={"cmd": "id"})[0] == 403


def test_nodes_proxy_holder_can_use_kubelet_endpoints():
    k = ks.Kubelet(GOOD, PODS, allowed={"admin": {"nodes/proxy"}})
    assert k.handle("GET", "/pods", user="admin")[0] == 200


def test_read_only_port():
    assert ks.Kubelet(BAD, PODS).handle("GET", "/pods", port=10255)[0] == 200
    assert ks.Kubelet(GOOD, PODS).handle("GET", "/pods", port=10255)[0] == 0
    assert ks.Kubelet(BAD, PODS).handle("POST", "/run/a/b/c", port=10255)[0] == 404


def test_audit_insecure_and_hardened():
    assert {f.rule_id for f in ks.audit_config(BAD)} >= {"KL-001", "KL-002", "KL-003", "KL-004", "KL-005"}
    assert ks.audit_config(GOOD) == []


def test_run_path_needs_three_parts():
    assert ks.Kubelet(BAD, PODS).handle("POST", "/run/shop/web-1")[0] == 404


def test_not_a_kubelet_config_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        ks.load_config("kind: Pod\n")
