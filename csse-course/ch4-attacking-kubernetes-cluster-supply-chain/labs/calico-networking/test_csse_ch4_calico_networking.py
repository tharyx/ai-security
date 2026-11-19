import copy
from pathlib import Path

import yaml
from aisec_lab import load_lab_module

np_ = load_lab_module(__file__, "netpol")
FIX = Path(__file__).parent / "fixtures"
C = yaml.safe_load((FIX / "cluster.yaml").read_text())
POLICIES = list(yaml.safe_load_all((FIX / "policies.yaml").read_text()))
PODS = [np_.Pod(p["name"], p["namespace"], p["labels"]) for p in C["pods"]]
BY = {p.name: p for p in PODS}


def cluster(policies):
    return np_.Cluster(PODS, C["namespaces"], policies)


def test_without_policies_everything_is_reachable():
    cl = cluster([])
    assert all(cl.matrix(80).values()) and len(np_.exposed_pods(cl)) == len(PODS)


def test_default_deny_plus_allows_gives_the_intended_chain():
    cl = cluster(POLICIES)
    assert cl.can_reach(BY["web"], BY["api"], 8080)
    assert cl.can_reach(BY["api"], BY["db"], 5432)
    assert not cl.can_reach(BY["web"], BY["db"], 5432)


def test_wrong_port_is_denied():
    assert not cluster(POLICIES).can_reach(BY["web"], BY["api"], 22)


def test_both_ends_must_allow():
    pols = [p for p in POLICIES if p["metadata"]["name"] != "web-egress-to-api"]
    assert not cluster(pols).can_reach(BY["web"], BY["api"], 8080)  # ingress allowed but egress is default-denied
    pols = [p for p in POLICIES if p["metadata"]["name"] != "web-to-api"]
    assert not cluster(pols).can_reach(BY["web"], BY["api"], 8080)


def test_other_namespace_cannot_reach_isolated_pods():
    cl = cluster(POLICIES)
    assert not cl.can_reach(BY["rogue"], BY["db"], 5432) and not cl.can_reach(BY["rogue"], BY["web"], 80)


def test_unselected_namespace_stays_open():
    cl = cluster(POLICIES)
    assert cl.can_reach(BY["rogue"], BY["payments-api"], 443)  # nothing isolates payments: add default deny there too
    assert "payments/payments-api" in np_.exposed_pods(cl)


def test_egress_from_shop_to_other_namespace_is_blocked_by_default_deny():
    assert not cluster(POLICIES).can_reach(BY["web"], BY["payments-api"], 443)


def test_namespace_selector_allows_cross_namespace():
    pols = copy.deepcopy(POLICIES)
    pols.append({"metadata": {"name": "from-payments", "namespace": "shop"},
                 "spec": {"podSelector": {"matchLabels": {"app": "api"}}, "policyTypes": ["Ingress"],
                          "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"team": "payments"}}}], "ports": [{"port": 8080}]}]}})
    pols.append({"metadata": {"name": "payments-egress", "namespace": "payments"},
                 "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"to": [{"namespaceSelector": {}}]}]}})
    cl = cluster(pols)
    assert cl.can_reach(BY["payments-api"], BY["api"], 8080)
    assert not cl.can_reach(BY["rogue"], BY["api"], 8080)


def test_pod_selector_alone_means_same_namespace():
    pols = copy.deepcopy(POLICIES)
    pols[1]["spec"]["ingress"][0]["from"] = [{"podSelector": {"matchLabels": {"app": "payments-api"}}}]
    assert not cluster(pols).can_reach(BY["payments-api"], BY["api"], 8080)


def test_match_expressions():
    assert np_.selector_matches({"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]}, {"app": "web"})
    assert not np_.selector_matches({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}, {"app": "web"})
    assert np_.selector_matches({}, {"a": "b"}) and not np_.selector_matches(None, {"a": "b"})
