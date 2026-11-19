"""Tests for the KubiScan-style RBAC risk finder."""

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "rbac_risk")
ROLES, BINDINGS = r.load()
RISKY = r.risky_subjects(ROLES, BINDINGS)


def subjects(severity=None):
    return {x["subject"] for x in RISKY if severity is None or x["severity"] == severity}


def test_wildcard_role_is_critical_and_bound_to_ci_account():
    assert "ServiceAccount:build/ci-runner" in subjects("critical")


def test_anonymous_group_reading_secrets_flagged():
    assert "Group:-/system:unauthenticated" in subjects("critical")
    assert any(x["why"] == "can read secrets" and x["subject"].endswith("system:unauthenticated") for x in RISKY)


def test_default_service_account_with_exec():
    assert any(x["subject"] == "ServiceAccount:shop/default" and "default service account" in x["why"] for x in RISKY)


def test_escalation_verbs_flagged():
    assert "User:-/dev@acme.example" in subjects("critical")


def test_read_only_viewer_group_not_flagged():
    assert "Group:-/team-shop" not in subjects()


def test_who_can_get_secrets_includes_wildcard_and_anonymous():
    w = r.who_can(ROLES, BINDINGS, "get", "secrets")
    assert "ServiceAccount:ci-runner" in w and "Group:system:unauthenticated" in w and "Group:team-shop" not in w


def test_who_can_exec():
    assert r.who_can(ROLES, BINDINGS, "create", "pods/exec") == ["ServiceAccount:ci-runner", "ServiceAccount:default"]


def test_results_sorted_critical_first():
    order = [r.SEV[x["severity"]] for x in RISKY]
    assert order == sorted(order)


def test_binding_to_missing_role_is_ignored():
    b = [{"kind": "ClusterRoleBinding", "metadata": {"name": "x"}, "roleRef": {"name": "ghost"}, "subjects": [{"kind": "User", "name": "u"}]}]
    assert r.risky_subjects(ROLES, b) == []
