# Lab: Reconnaissance using Kube-hunter (legacy tool, current ideas)

**Course exercise:** "Reconnaissance using Kube-hunter". Lessons: [04 sections 3.1 and 5](../../04-common-attack-vectors-in-kubernetes-clusters.md#5-recon-tools-legacy-versus-current).

> **Outdated → current.** kube-hunter (Aqua Security) is **no longer actively developed**; Aqua recommends **Trivy** (`trivy k8s`) for cluster scanning. This lab keeps the recon *ideas* and tells you which modern tools cover them. Use `trivy k8s`, Kubescape and kube-bench for real work, and only on clusters you own or are authorised to test.

**Time:** 45 minutes. **Safety:** nothing is scanned. The input is a JSON inventory with RFC 5737 documentation IPs (`203.0.113.x`).

## What it does

[recon.py](recon.py) turns an endpoint inventory (`host`, `port`, `service`, anonymous probe results) into a report:

| ID | Finding |
|---|---|
| REC-001 to REC-003 | API server answers anonymous reads; only `/version` is open; insecure port 8080 |
| REC-010 to REC-012 | kubelet lists pods anonymously; `/run` reachable; read-only port 10255 |
| REC-020 | etcd answers without a client certificate |
| REC-030, REC-031 | dashboard without authentication; exposed externally |
| REC-040 | sensitive port reachable from a public address |

The report starts with the legacy banner and ends with "Modern follow-up" tool suggestions.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kube-hunter-recon/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kube-hunter-recon -v
```

1. Read the report. Which single finding would you fix first? (The open API server or dashboard: they hand over the cluster.)
2. Edit the fixture so the API server returns 403 for `/api/v1/namespaces`: REC-001 becomes REC-002.
3. Think: a hardened API server still answers `/version` to anonymous callers by default. Is that a vulnerability? (A low-severity information disclosure; restrict by network.)

## Expected output (real run, abridged)

```text
kube-hunter is legacy (no longer actively developed). Use `trivy k8s` or Kubescape for real scans; this report keeps its recon ideas.

Findings: 9
  [CRITICAL] REC-001 203.0.113.11:6443: API server answers anonymous requests to read cluster objects
  [CRITICAL] REC-010 203.0.113.21:10250: kubelet lists pods to anonymous callers ...
  [CRITICAL] REC-030 203.0.113.40:8443: dashboard is exposed without authentication
  [LOW     ] REC-002 203.0.113.10:6443: anonymous users can read /version ...
```

## Real tools

See [real-tools/trivy-k8s.md](../../real-tools/trivy-k8s.md) and [real-tools/kubescape.md](../../real-tools/kubescape.md).
