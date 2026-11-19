from pathlib import Path

import yaml
from aisec_lab import load_lab_module

sp = load_lab_module(__file__, "secret_paths")
DOCS = [d for d in yaml.safe_load_all((Path(__file__).parent / "fixtures/rbac.yaml").read_text()) if d]


def paths_for(subject):
    return {(p.path_id, p.namespace) for p in sp.analyse(DOCS) if p.subject == subject}


def test_cluster_wide_list_secrets_is_critical():
    found = [p for p in sp.analyse(DOCS) if p.subject == "sa:shop:metrics" and p.path_id == "SEC-001"]
    assert found and found[0].severity == "CRITICAL" and found[0].namespace == "*"


def test_developer_exec_and_create_pods_only_in_their_namespace():
    got = paths_for("user:alice@example.org")
    assert ("SEC-002", "shop") in got and ("SEC-003", "shop") in got
    assert not any(ns == "payments" for _, ns in got)


def test_ci_can_escalate_and_impersonate():
    got = {pid for pid, _ in paths_for("sa:payments:ci")}
    assert {"SEC-005", "SEC-007"} <= got


def test_named_secret_get_is_the_good_pattern_and_not_flagged():
    assert [x for x in sp.analyse(DOCS) if x.subject == "sa:shop:web"] == []


def test_dropping_resource_names_turns_it_into_a_finding():
    docs = [dict(d) for d in DOCS]
    for d in docs:
        if d["kind"] == "Role" and d["metadata"]["name"] == "read-own-secret":
            d["rules"] = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
    assert any(x.subject == "sa:shop:web" and x.path_id == "SEC-001" and x.severity == "HIGH" for x in sp.analyse(docs))


def test_wildcard_is_critical():
    docs = DOCS + [
        {"kind": "ClusterRole", "metadata": {"name": "all"}, "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
        {"kind": "ClusterRoleBinding", "metadata": {"name": "all-b"}, "subjects": [{"kind": "User", "name": "bob"}],
         "roleRef": {"kind": "ClusterRole", "name": "all", "apiGroup": "rbac.authorization.k8s.io"}},
    ]
    got = {p.path_id for p in sp.analyse(docs) if p.subject == "user:bob"}
    assert {"SEC-008", "SEC-001", "SEC-002", "SEC-005", "SEC-007"} <= got


def test_pod_paths_find_the_metrics_agent_and_skip_automount_false():
    lines = sp.pod_paths(DOCS)
    assert any("metrics-agent" in line and "SEC-001" in line for line in lines)
    assert not any("web-1" in line for line in lines)


def test_allows_respects_namespace_scope():
    grants = sp.build_grants(DOCS)["user:alice@example.org"]
    assert sp.allows(grants, "shop", "create", "pods/exec")
    assert not sp.allows(grants, "payments", "create", "pods/exec")


def test_verb_and_resource_wildcards():
    g = [("*", {"apiGroups": [""], "resources": ["*"], "verbs": ["get"]})]
    assert sp.allows(g, "x", "get", "secrets") and not sp.allows(g, "x", "delete", "secrets")
