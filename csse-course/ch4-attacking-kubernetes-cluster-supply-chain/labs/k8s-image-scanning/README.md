# Lab: Kubernetes image scanning

**Course exercise:** "Kubernetes image scanning". Lessons: [05 section 2](../../05-securing-container-orchestration.md#2-static-analysis-of-kubernetes-clusters). Related: [chapter 3 Trivy guide](../../../ch3-attacking-container-supply-chain/real-tools/trivy.md).

**Time:** 45 minutes. **Safety:** offline. The vulnerability database is a **synthetic fixture** (`CVE-2099-xxxx` are not real). No image is pulled.

## What it does

[image_scan.py](image_scan.py):

1. **Extracts every image** from Deployments, Pods, Jobs, CronJobs (init containers included).
2. **Looks each image up** in the local DB by digest (preferred) or by `repo:tag` (Docker Hub shortcuts expanded).
3. **Applies a policy:** allowed registries, max critical and high counts, and **digest pinning**.
4. **Reports** counts, fixable packages and problems, and a pass/fail **gate**.

Why digests matter here: a scan result belongs to **one image digest**. If the manifest uses a tag, the thing that runs may differ from the thing you scanned.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-image-scanning/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-image-scanning -v
```

1. Read the five images. Which one is "never scanned"? Why is an unscanned image worse than one with known issues? (Unknown risk.)
2. Pin `registry.corp.example/shop/api:1.4` by a digest and add that digest to the DB with fewer findings: the problems shrink.
3. Relax the policy (see `test_relaxed_policy_changes_the_outcome`) and note what you are choosing to accept.

## Expected output (real run, abridged)

```text
registry.corp.example/shop/api:1.4
   counts {'CRITICAL': 1, 'HIGH': 3, 'MEDIUM': 0, 'LOW': 0}
   PROBLEM: not pinned by digest: the scanned image may differ from what runs
   PROBLEM: 1 critical vulnerabilities (max 0)
   PROBLEM: 3 high vulnerabilities (max 2)
   fixable: ['web-framework-example -> 5.0.3', 'libexample -> 2.4.1', 'yaml-example -> 0.9']
ghcr.io/someone/tools:latest
   PROBLEM: never scanned: no entry in the vulnerability database
GATE: FAIL
```

## Real tools

`trivy image`, `trivy k8s --report summary cluster`, Grype, Kubescape image scanning, Harbor scan-on-push, admission policies that require a signature or a scan attestation. See [real-tools/trivy-k8s.md](../../real-tools/trivy-k8s.md).
