# Real tool guide: Kubescape (CNCF) for manifests, charts and clusters

> **Hedged guide.** Not run by the repo author for this guide. Check kubescape.io and `kubescape --help` for current commands, frameworks and output formats. Some features need network access or an account; the core CLI scans locally.

Kubescape is an open-source Kubernetes security scanner (a CNCF project). It checks **manifests, Helm charts, live clusters** and images against frameworks such as NSA/CISA hardening, MITRE ATT&CK, CIS benchmarks (names and coverage change, verify).

## Typical commands (concept)

```text
kubescape scan framework nsa deploy.yaml                 # scan manifest files
kubescape scan framework nsa ./chart-dir                 # a chart directory (renders it)
kubescape scan --format json --output result.json        # scan the current cluster context
kubescape scan control C-0057                            # one control (example ID: privileged container; verify IDs)
```

## What it adds beyond a manifest linter

- **Risk scores** per control and per resource.
- **RBAC checks** (wildcards, secrets access, escalation), covering the same ground as the [stealing-k8s-secrets lab](../labs/stealing-k8s-secrets/README.md).
- **Image scanning** and misconfiguration scanning (some via Trivy or Grype libraries; verify).
- An **operator** for continuous in-cluster scans.

## Map to the labs

| Lab | Kubescape equivalent |
|---|---|
| privileged-pods | Controls for privileged, hostPath, hostPID, capabilities |
| static-analysis-manifests | `kubescape scan` on manifests and rendered charts |
| stealing-k8s-secrets | RBAC controls (list secrets, exec, impersonate) |
| kube-hunter-recon (legacy) | Cluster posture scan instead of port probing |

## Alternatives and companions

`trivy k8s` / `trivy config` ([guide](trivy-k8s.md)), kube-linter, Polaris, Checkov, kube-bench (CIS node and control plane), Kyverno policy reports, KubiScan (check maintenance status first), rbac-tool, kubectl-who-can.

## Cautions

- Scanner output is a **list of hypotheses**. Exclude intentional exceptions explicitly and record why.
- Do not scan clusters you do not own or administer.
