"""Demo: audit two GKE fixtures and show pod identity from metadata."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gke_audit  # noqa: E402

doc = gke_audit.load(HERE / "fixtures" / "clusters.json")
for f in gke_audit.audit(doc):
    print(f"[{f.severity:8}] {f.cluster:14} {f.rule:22} {f.detail[:68]}")
print()
clusters = {c["name"]: c for c in doc["clusters"]}
for p in doc["pods"]:
    print(f"{p['cluster']:14} {p['name']:8} token request returns -> {gke_audit.pod_identity_from_metadata(clusters[p['cluster']], p)}")
