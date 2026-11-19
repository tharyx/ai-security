# Lab: Working with Kubernetes

**Course exercise:** "Working with Kubernetes". Lessons: [01 section 4.3](../../01-microservices-and-kubernetes.md#43-objects-you-will-see).

**Time:** 45 minutes. **Safety:** fixtures only; nothing is applied to any cluster.

## What it does

[validate.py](validate.py) checks that a Deployment, Service and Ingress fit together:

| ID | Check |
|---|---|
| WK-001 | `spec.selector` matches the pod template labels |
| WK-002, WK-003 | readiness probe present; image not untagged or `latest` |
| WK-010, WK-011 | Service selector matches pods; `targetPort` (number or name) exists on a container |
| WK-012 | NodePort or LoadBalancer exposure is flagged for review |
| WK-020 to WK-023 | Ingress has TLS; backend Service and port exist; ssl-redirect not disabled |

[fixtures/good.yaml](fixtures/good.yaml) passes; [fixtures/broken.yaml](fixtures/broken.yaml) has seven problems.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/working-with-kubernetes/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/working-with-kubernetes -v
```

1. Fix `broken.yaml` one issue at a time until the validator is silent.
2. Change the Service `targetPort` in `good.yaml` to a named port that does not exist.
3. Think: which of these are functional bugs and which are security issues? (WK-020 and WK-012 are exposure risks; WK-010 means a Service with no endpoints, which can also hide a typo-squatted label.)

## Expected output (real run, abridged)

```text
== good.yaml: 0 issue(s) ==
== broken.yaml: 7 issue(s) ==
  [HIGH  ] WK-001 Deployment/shop/web: spec.selector does not match template labels ...
  [MEDIUM] WK-003 Deployment/shop/web: image nginx:latest is untagged or latest
  [HIGH  ] WK-020 Ingress/shop/web: no TLS section: traffic is plain HTTP
  [HIGH  ] WK-021 Ingress/shop/web: backend Service webb does not exist
```

(The real output also lists WK-002, WK-011, WK-012 and WK-023.) Real twins: `kubectl apply --dry-run=server`, kubeconform, kube-linter.
