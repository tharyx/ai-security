# Lab: Privileged pods in Kubernetes

**Course exercise:** "Privileged pods in Kubernetes". Lessons: [03 section 2.3](../../03-abusing-the-kubernetes-request-pipeline.md#23-admission-control-is-this-object-acceptable), [04 section 3.4](../../04-common-attack-vectors-in-kubernetes-clusters.md#34-privileged-and-over-powerful-pods). Related: [chapter 3 exploit-containerized-app](../../../ch3-attacking-container-supply-chain/labs/exploit-containerized-app/README.md).

**Time:** 60 minutes. **Safety:** manifests are only read and classified; nothing is applied. No exploit code.

## What it does

[pod_escape.py](pod_escape.py):

- **Detects** privileged containers, `hostPID`/`hostNetwork`/`hostIPC`, `hostPath` volumes (root, runtime sockets, narrow), extra capabilities, `SYS_ADMIN`.
- **Classifies** each pod by the **Pod Security Standards** (subset): `privileged`, `baseline`, `restricted` (the strictest level the pod meets). PSA enforces these per namespace with `pod-security.kubernetes.io/enforce=<level>` labels.
- **Explains** escape paths ("host files, kubelet credentials or the runtime socket").
- **Cross-checks** with the module-06 manifest linter ([k8s_policy.py](../../../../06-ai-devsecops/kubernetes/lab/k8s_policy.py), loaded by path).

PodSecurityPolicy was removed in Kubernetes 1.25. PSA, ValidatingAdmissionPolicy and Kyverno/Gatekeeper replace it.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/privileged-pods/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/privileged-pods -v
```

1. Read the four pods' levels. Why is the "log collector" (read-only `/var/log` hostPath) still `privileged` level? (hostPath volumes are not allowed by baseline. Prefer a sidecar or a log agent with a narrow, audited exception in a dedicated namespace.)
2. Make `web-baseline` restricted: add the pod `securityContext` and container settings step by step; watch `restricted` violations shrink.
3. Try the mutations in `test_each_restricted_requirement_matters` by hand.

## Expected output (real run)

```text
Pod/debug-priv       PSS level: privileged escapes: ['privileged', 'hostPath', 'hostPID+ptrace']
    blocks baseline : hostPID=true
    blocks baseline : hostPath volume /
    blocks baseline : container shell privileged
Pod/log-collector    PSS level: privileged escapes: ['hostPath-narrow']
Pod/web-baseline     PSS level: baseline   escapes: []
Pod/web-restricted   PSS level: restricted escapes: []
```

## Real tools

Pod Security Admission (labels), Kubescape, kube-linter, `trivy k8s`, Kyverno/Gatekeeper policies. Verify the exact policy tables at kubernetes.io (Pod Security Standards).
