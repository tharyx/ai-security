# Real tool guide: `trivy k8s` (the current replacement for kube-hunter-style scanning)

> **Hedged guide.** Not run by the repo author for this guide. kube-hunter (Aqua Security) is **no longer actively developed** and Aqua recommends Trivy for cluster scanning (verify at the kube-hunter repository). The `trivy k8s` command surface has changed between Trivy versions: always check `trivy k8s --help` and trivy.dev docs. The first run downloads vulnerability and check databases, so it needs network access.

## What it scans

`trivy k8s` connects to your **current kubeconfig context** (read access) and scans:

- **Vulnerabilities** in images used by workloads,
- **Misconfigurations** in workload and RBAC objects,
- **Exposed secrets** in images and manifests,
- **RBAC** assessment (risky roles and bindings),
- optionally **SBOMs** for cluster images.

## Typical commands (concept)

```text
trivy k8s --report summary cluster                      # high-level view of the whole cluster
trivy k8s --report all --namespace shop deployment/web  # details for one workload
trivy k8s --scanners misconfig,rbac cluster             # configuration only (flags vary by version)
trivy config ./manifests                                # offline-ish: scan manifests or a Helm chart directory
trivy image --severity HIGH,CRITICAL registry.corp.example/shop/web@sha256:<digest>
```

## Map from legacy kube-hunter ideas

| kube-hunter idea | Today |
|---|---|
| "Is the API server or kubelet open to anonymous users?" | CIS checks with kube-bench; network posture with your firewall and cloud tooling; Kubescape and `trivy k8s` cover config and RBAC |
| Passive discovery of nodes and services | Cloud asset inventory and Kubernetes API listing with a read-only role |
| Active exploit hunting | Authorised penetration testing with a scope and rules of engagement |
| Report | `trivy k8s --report summary`, SARIF or JSON into DefectDojo or your ticket system |

## Map to the labs

| Lab | Trivy |
|---|---|
| kube-hunter-recon | `trivy k8s` and kube-bench in place of the legacy tool |
| k8s-image-scanning | `trivy image` for each image from the manifest; `trivy k8s` for what is running |
| static-analysis-manifests | `trivy config` on manifests and chart directories |

## Cautions

- Use a **read-only** identity for scans.
- Results include false positives; triage them. Track accepted risks.
- Pin Trivy versions in CI, and mirror the databases if CI is offline.
