# Lab: Finding Misconfigurations Using Kubescape

**Course exercise:** "Finding Misconfigurations Using Kubescape". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 50 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Kubescape**. Kubescape is a CNCF project and actively maintained (verify). Control IDs here (`KL-xx`) are local and do **not** equal Kubescape control IDs. For Kubernetes attack concepts see [chapter 4](../../../ch4-attacking-kubernetes-cluster-supply-chain/README.md); for manifest linting in this repo see [06 kubernetes](../../../../06-ai-devsecops/kubernetes/README.md).

## What the offline twin does

`manifest_scan.py` runs **11 workload controls** over YAML: privileged, host namespaces, root user, privilege escalation, writable root filesystem, capabilities, resource limits, mutable image tags, plain-text secret env vars, service-account token automount, hostPath. It supports **frameworks** (control sets), **exceptions** and a **compliance score**.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubescape-manifest-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubescape-manifest-scan -v
```

1. Run the demo: the BAD and GOOD Deployments.
2. Fix BAD one control at a time and watch the score rise to 100.
3. Why is `latest` a supply-chain problem and not only a hygiene problem? (The tag can change under you.)

## Expected output (real run)

```text
== BAD: 10 failed checks, compliance 9%
   KL-02 high     Host network/PID/IPC                         Deployment/web (pod)
   KL-10 low      Service account token auto-mounted           Deployment/web (pod)
   KL-01 critical Privileged container                         Deployment/web (container web)
   KL-03 high     Runs as root (runAsNonRoot not set)          Deployment/web (container web)
   KL-04 medium   allowPrivilegeEscalation not disabled        Deployment/web (container web)
   KL-05 medium   Writable root filesystem                     Deployment/web (container web)
   KL-06 medium   Capabilities not dropped                     Deployment/web (container web)
   KL-07 medium   No resource limits                           Deployment/web (container web)
   KL-08 medium   Image tag is mutable (latest or missing)     Deployment/web (container web)
   KL-09 high     Secret-looking env var in plain text         Deployment/web (container web)
== GOOD: 0 failed checks, compliance 100%
supply-chain framework only (BAD): ['KL-08', 'KL-09']
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
kubescape scan deployment.yaml                         # scan a manifest file
kubescape scan framework nsa deployment.yaml           # a named framework (check names with `kubescape list frameworks`)
kubescape scan --format json --output results.json .
kubescape scan                                         # scan the current cluster context (read-only; use a test cluster)
trivy k8s --report summary cluster                     # Trivy's cluster scan (kube-hunter's recommended successor)
```
Cluster scans need cluster access. Use a disposable local cluster (kind or minikube) if you have the resources; the tests do not need one.
