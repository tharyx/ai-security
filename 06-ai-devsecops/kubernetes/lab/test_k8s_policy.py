"""Kubernetes policy tests: every rule fires on the vulnerable manifests, none on the secure
ones, and single edits prove each rule catches the exposure it is named after.

Run from the repository root:
    python -m pytest 06-ai-devsecops/kubernetes -v
"""

import copy
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

kp = load_lab_module(__file__, "k8s_policy")
LAB = Path(__file__).parent
VULN = kp.load_docs(LAB / "vulnerable" / "model-server.yaml")
SECURE = kp.load_docs(LAB / "secure" / "model-server.yaml", LAB / "secure" / "admission-policy.yaml")


def ids(docs) -> set[str]:
    return {f.rule_id for f in kp.check(docs)}


def find(docs, kind: str, name: str) -> dict:
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def secure_copy():
    docs = copy.deepcopy(SECURE)
    return docs, find(docs, "Deployment", "llm-server")["spec"]["template"]["spec"]


# ---------- Part 1 and 2: vulnerable vs secure -----------------------------------------

def test_vulnerable_manifests_trigger_every_rule():
    assert ids(VULN) == set(kp.RULES)
    assert kp.main([str(LAB / "vulnerable" / "model-server.yaml")]) == 1


def test_secure_manifests_are_clean():
    assert kp.check(SECURE) == []
    assert kp.main([str(LAB / "secure" / "model-server.yaml")]) == 0


# ---------- Part 3: network isolation -------------------------------------------------------

def test_removing_default_deny_is_caught():
    docs = [d for d in copy.deepcopy(SECURE) if d["metadata"]["name"] != "default-deny-all"]
    assert "K8S-013" in ids(docs)


def test_ingress_only_default_deny_is_not_enough():
    docs = copy.deepcopy(SECURE)
    find(docs, "NetworkPolicy", "default-deny-all")["spec"]["policyTypes"] = ["Ingress"]
    assert "K8S-013" in ids(docs)  # egress is where exfiltration and C2 happen


@pytest.mark.parametrize("rule", [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}, {}])
def test_internet_egress_is_caught(rule):
    docs = copy.deepcopy(SECURE)
    find(docs, "NetworkPolicy", "allow-llm-egress")["spec"]["egress"].append(rule)
    assert "K8S-014" in ids(docs)


def test_internal_load_balancer_is_allowed():
    docs = copy.deepcopy(SECURE)
    svc = find(docs, "Service", "llm-server")
    svc["spec"]["type"] = "LoadBalancer"
    assert "K8S-015" in ids(docs)
    svc["metadata"]["annotations"] = {"service.beta.kubernetes.io/aws-load-balancer-internal": "true"}
    assert "K8S-015" not in ids(docs)


# ---------- Part 4: pod hardening ---------------------------------------------------------------

def test_container_setting_overrides_pod_setting():
    docs, pod = secure_copy()
    pod["containers"][0]["securityContext"]["runAsUser"] = 0  # pod says non-root, container says root
    assert "K8S-002" in ids(docs)


def test_privileged_is_caught():
    docs, pod = secure_copy()
    pod["containers"][0]["securityContext"]["privileged"] = True
    assert "K8S-001" in ids(docs)


def test_cronjob_pod_spec_is_checked_too():
    docs = copy.deepcopy(SECURE)
    _, pod = secure_copy()
    pod = copy.deepcopy(pod)
    pod["hostPID"] = True
    docs.append({"apiVersion": "batch/v1", "kind": "CronJob",
                 "metadata": {"name": "reindex", "namespace": "ml-serving"},
                 "spec": {"schedule": "0 * * * *", "jobTemplate": {"spec": {"template": {"spec": pod}}}}})
    assert "K8S-006" in ids(docs)


def test_gpu_pod_without_toleration_is_caught_but_cpu_pod_is_fine():
    docs, pod = secure_copy()
    pod["tolerations"] = []
    assert "K8S-017" in ids(docs)
    for c in pod["containers"]:
        for section in c["resources"].values():
            section.pop("nvidia.com/gpu")
    assert "K8S-017" not in ids(docs)  # no GPU, no GPU-pool requirement


# ---------- Part 5: secrets and identity ----------------------------------------------------------

def test_literal_secret_is_caught_but_reference_is_fine():
    docs, pod = secure_copy()
    env = pod["containers"][0]["env"]
    assert any(e["name"] == "GATEWAY_SHARED_TOKEN" and "valueFrom" in e for e in env)
    assert "K8S-009" not in ids(docs)
    env.append({"name": "HF_TOKEN", "value": "hf_CANARYCANARYCANARYCANARY"})
    assert "K8S-009" in ids(docs)


def test_static_cloud_key_from_a_secret_is_still_a_static_key():
    docs, pod = secure_copy()
    pod["containers"][0]["env"].append(
        {"name": "AWS_SECRET_ACCESS_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "v"}}})
    assert "K8S-010" in ids(docs)


def test_service_account_setting_is_honoured():
    docs, pod = secure_copy()
    pod.pop("automountServiceAccountToken")
    assert "K8S-011" not in ids(docs)  # the ServiceAccount itself says false
    find(docs, "ServiceAccount", "llm-server").pop("automountServiceAccountToken")
    assert "K8S-011" in ids(docs)


def test_role_that_reads_secrets_is_caught():
    docs = copy.deepcopy(SECURE)
    docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": "reader", "namespace": "ml-serving"},
                 "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]})
    assert "K8S-016" in ids(docs)


def test_undeclared_namespace_fails_closed():
    docs = [d for d in copy.deepcopy(SECURE) if d["kind"] != "Namespace"]
    assert "K8S-012" in ids(docs)


def test_manifests_are_parsed_with_safe_load():
    """A malicious manifest must not be able to run code in the checker itself."""
    evil = "kind: Pod\nmetadata: !!python/object/apply:os.system ['echo CANARY']\n"
    with pytest.raises(yaml.YAMLError):
        list(yaml.safe_load_all(evil))
