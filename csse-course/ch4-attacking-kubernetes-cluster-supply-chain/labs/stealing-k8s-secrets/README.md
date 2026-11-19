# Lab: Stealing Kubernetes secrets

**Course exercise:** "Stealing Kubernetes secrets". Lessons: [03 section 4](../../03-abusing-the-kubernetes-request-pipeline.md#4-insecure-rbac-rules), [04 section 3.2 to 3.3](../../04-common-attack-vectors-in-kubernetes-clusters.md).

**Time:** 60 minutes. **Safety:** this lab is an **analyzer**. It reads RBAC and pod manifests and reports paths; it never reads a Secret and never talks to a cluster.

## What it finds

[secret_paths.py](secret_paths.py) builds subject-to-permission grants (RoleBindings give a namespace, ClusterRoleBindings give `*`) and reports paths to Secrets:

| ID | Path |
|---|---|
| SEC-001 | `get/list/watch` secrets (list and watch return every value in scope: CRITICAL) |
| SEC-002 | `create pods`: mount any Secret or SA token |
| SEC-003 | `pods/exec`: read env, files and token inside a pod |
| SEC-004 | `serviceaccounts/token`: mint tokens |
| SEC-005 | `impersonate` |
| SEC-006 | `nodes/proxy`: kubelet API |
| SEC-007 | `escalate`, `bind`, create bindings |
| SEC-008 | wildcard verbs and resources |
| SEC-010 | `patch`/`update` workloads |

It also lists **pods whose service-account token carries such power** (`pod_paths`), skipping pods with `automountServiceAccountToken: false`. Rules limited with `resourceNames` are treated as the good narrow pattern.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/stealing-k8s-secrets/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/stealing-k8s-secrets -v
```

1. Read the demo. Why is the metrics service account CRITICAL even though "it only monitors"? (`secrets` in a cluster-wide list rule.)
2. Remove `secrets` from the `metrics-reader` ClusterRole; re-run.
3. Give `read-own-secret` no `resourceNames` and see `web` become a finding (test `test_dropping_resource_names_turns_it_into_a_finding`).
4. Limits: the analyzer ignores aggregated ClusterRoles, group nesting beyond the common cases, admission controls, and cloud IAM. Use real tools for completeness.

## Expected output (real run)

```text
== RBAC paths to secrets ==
  [CRITICAL] sa:payments:ci         ns=*         SEC-005: impersonation lets them act as a more privileged identity
  [CRITICAL] sa:payments:ci         ns=*         SEC-007: can grant itself or others more permissions (escalate, bind, or create bindings)
  [CRITICAL] sa:shop:metrics        ns=*         SEC-001: can read Secrets: list/watch returns every Secret value in the namespace
  [CRITICAL] user:alice@example.org ns=shop      SEC-002: can create pods, so a pod can mount any Secret or service-account token in the namespace
  [HIGH    ] user:alice@example.org ns=shop      SEC-003: pods/exec lets them run commands in a pod and read its env, mounted secrets and SA token
== pods whose token carries that power ==
  Pod/shop/metrics-agent (sa metrics) -> ['SEC-001']
```

## Real tools

`kubectl auth can-i --list --as ...`, kubectl-who-can, rbac-tool, Kubescape (RBAC controls). KubiScan is a known RBAC-risk tool whose maintenance status you should check before relying on it.
