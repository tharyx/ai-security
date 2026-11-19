"""Tests for the GKE fixture auditor."""

from pathlib import Path

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "gke_audit")
DOC = g.load(Path(__file__).resolve().parent / "fixtures" / "clusters.json")
C = {c["name"]: c for c in DOC["clusters"]}


def rules(name):
    return {f.rule for f in g.audit_cluster(C[name])}


def test_legacy_cluster_has_the_headline_problems():
    r = rules("prod-legacy")
    assert {"LEGACY-ABAC", "LEGACY-METADATA", "NO-WORKLOAD-IDENTITY", "DEFAULT-NODE-SA", "METADATA-MODE"} <= r


def test_legacy_abac_is_critical():
    assert any(f.rule == "LEGACY-ABAC" and f.severity == "critical" for f in g.audit_cluster(C["prod-legacy"]))


def test_default_sa_with_editor_is_critical():
    assert any(f.rule == "SA-BROAD-ROLE" and f.severity == "critical" for f in g.audit_cluster(C["prod-legacy"]))


def test_hardened_cluster_is_clean():
    assert g.audit_cluster(C["prod-hardened"]) == []


def test_pod_on_legacy_cluster_gets_node_sa_with_editor():
    pod = DOC["pods"][0]
    ident = g.pod_identity_from_metadata(C["prod-legacy"], pod)
    assert "default-compute" in ident and "roles/editor" in ident


def test_workload_identity_pod_gets_only_its_bound_gsa():
    pod = DOC["pods"][1]
    assert g.pod_identity_from_metadata(C["prod-hardened"], pod) == "web-gsa@acme.example"


def test_unbound_pod_on_workload_identity_gets_no_node_identity():
    pod = DOC["pods"][2]
    assert "node SA" not in g.pod_identity_from_metadata(C["prod-hardened"], pod)


def test_open_control_plane_and_public_nodes():
    assert {"OPEN-CONTROL-PLANE", "PUBLIC-NODES", "NO-BINARY-AUTH"} <= rules("prod-legacy")


def test_audit_sorted_and_only_for_bad_cluster():
    f = g.audit(DOC)
    assert f[0].severity == "critical" and {x.cluster for x in f} == {"prod-legacy"}


def test_enabling_workload_identity_alone_does_not_fix_pool_metadata_mode():
    c = dict(C["prod-legacy"], workload_identity=True)
    assert "METADATA-MODE" in {f.rule for f in g.audit_cluster(c)}
    assert "node SA" in g.pod_identity_from_metadata(c, DOC["pods"][0])
