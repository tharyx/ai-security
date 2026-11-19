"""Audit GKE cluster fixtures and simulate what a compromised pod can obtain from metadata. Offline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    cluster: str
    detail: str


def audit_cluster(c):
    n, out = c["name"], []

    def add(rule, sev, detail):
        out.append(Finding(rule, sev, n, detail))

    if c.get("legacy_abac"):
        add("LEGACY-ABAC", "critical", "legacy attribute-based authorization lets every service account act broadly; use RBAC only")
    if c.get("legacy_metadata_endpoints"):
        add("LEGACY-METADATA", "high", "legacy /0.1/ and /v1beta1/ metadata endpoints are served (no Metadata-Flavor header needed)")
    if not c.get("workload_identity"):
        add("NO-WORKLOAD-IDENTITY", "high", "pods fall back to the node service account")
    for pool in c["node_pools"]:
        if pool["service_account"] == "default-compute":
            add("DEFAULT-NODE-SA", "high", f"pool {pool['name']} uses the default Compute service account")
        if "cloud-platform" in pool["oauth_scopes"]:
            add("BROAD-OAUTH-SCOPE", "medium", f"pool {pool['name']} grants the cloud-platform scope")
        if pool["metadata_mode"] != "GKE_METADATA":
            add("METADATA-MODE", "high", f"pool {pool['name']} exposes the node metadata server to pods")
    if "roles/editor" in c.get("default_compute_sa_roles", []) or "roles/owner" in c.get("default_compute_sa_roles", []):
        add("SA-BROAD-ROLE", "critical", "default Compute SA holds Editor/Owner on the project")
    if not c.get("private_nodes"):
        add("PUBLIC-NODES", "medium", "nodes have public IPs")
    if not c.get("master_authorized_networks"):
        add("OPEN-CONTROL-PLANE", "high", "no authorized networks restrict the API server")
    if c.get("client_certificate_auth"):
        add("CLIENT-CERT-AUTH", "medium", "legacy client certificate authentication is enabled")
    if not c.get("network_policy"):
        add("NO-NETWORK-POLICY", "medium", "no network policy enforcement: flat pod network")
    if not c.get("shielded_nodes"):
        add("NO-SHIELDED-NODES", "low", "Shielded GKE Nodes are off")
    if not c.get("binary_authorization"):
        add("NO-BINARY-AUTH", "medium", "images are not verified at admission (Binary Authorization off)")
    if c.get("release_channel") in (None, "UNSPECIFIED"):
        add("NO-RELEASE-CHANNEL", "low", "no release channel: patching is manual")
    return out


def audit(doc):
    out = [f for c in doc["clusters"] for f in audit_cluster(c)]
    return sorted(out, key=lambda f: (SEV[f.severity], f.cluster, f.rule))


def pod_identity_from_metadata(cluster, pod) -> str:
    """Which identity does a token request from inside this pod return?"""
    pool = cluster["node_pools"][0]
    if cluster.get("workload_identity") and pool["metadata_mode"] == "GKE_METADATA":
        return pod["gsa_binding"] or "no Google identity (workload identity pool principal only)"
    return f"node SA: {pool['service_account']} (roles: {', '.join(cluster['default_compute_sa_roles']) or 'none'})"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
