# Kubescape and Trivy for Kubernetes (hedged)

> Kubescape is a CNCF project, actively maintained (verify). **kube-hunter** is no longer actively developed; Aqua recommends Trivy (`trivy k8s`) for cluster scanning. **PodSecurityPolicy** was removed in Kubernetes 1.25: use Pod Security Admission, ValidatingAdmissionPolicy (CEL), Kyverno or Gatekeeper. **Helm 4** was released in Nov 2025 (verify the details).

## Kubescape

```text
kubescape scan deployment.yaml                         # a manifest
kubescape scan framework nsa .                         # a framework over a folder (list: kubescape list frameworks)
kubescape scan --format json --output results.json .
kubescape scan                                         # live cluster of the current context (read-only; use a test cluster)
kubescape scan ./chart                                 # a Helm chart directory (verify support) or render first with helm template
```

Kubescape also has an in-cluster operator for continuous scanning and a view of RBAC-related risks (verify features).

## Trivy for clusters and manifests

```text
trivy config k8s/                                     # misconfigurations in manifests
trivy k8s --report summary cluster                     # live cluster
```

## RBAC helpers

```text
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl who-can get secrets -n <ns>                    # kubectl-who-can plugin
rbac-tool who-can get secrets                          # rbac-tool
```

## Disposable cluster for practice (optional)

kind or minikube on your laptop need disk and memory; skip if limited. Never run scans with admin credentials against a cluster you do not own.

## Labs

[kubescape-manifest-scan](../labs/kubescape-manifest-scan/README.md) · [kubescape-helm-scan](../labs/kubescape-helm-scan/README.md) · [kubiscan-rbac](../labs/kubiscan-rbac/README.md) · repo [06 kubernetes](../../../06-ai-devsecops/kubernetes/README.md) · [chapter 4](../../ch4-attacking-kubernetes-cluster-supply-chain/README.md)
