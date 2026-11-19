# Lab: Find Misconfigured RBAC Using KubiScan

**Course exercise:** "Find Misconfigured RBAC Using KubiScan". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **KubiScan**. **Check KubiScan's maintenance status before relying on it.** Alternatives: kubectl-who-can, rbac-tool, Kubescape's RBAC controls, `kubectl auth can-i --list`.

## What the offline twin does

`rbac_risk.py` loads **Role/ClusterRole and Binding YAML**, flags risky rules (wildcards, secrets read, `pods/exec`, `bind`/`escalate`/`impersonate`), risky subjects (anonymous groups, default service accounts, CI accounts with cluster-wide rights) and answers `who_can(verb, resource)` like kubectl-who-can.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubiscan-rbac/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubiscan-rbac -v
```

1. Run the demo. Which binding is the most dangerous and why?
2. Add a role that allows `create` on `pods` to a group; what does the tool say? (Creating pods can mount secrets and run privileged.)
3. Write the fix for the anonymous binding.

## Expected output (real run)

```text
[critical] Group:-/system:unauthenticated     via anon-secrets     granted to anonymous/unauthenticated users
[critical] ServiceAccount:build/ci-runner     via ci-admin         wildcard verbs and resources (cluster-admin equivalent)
[critical] User:-/dev@acme.example            via dev-escalate     can escalate privileges through RBAC verbs
[high    ] Group:-/system:unauthenticated     via anon-secrets     can read secrets
[high    ] ServiceAccount:build/ci-runner     via ci-admin         can read secrets
[high    ] ServiceAccount:shop/default        via default-sa-exec  can exec into pods
[medium  ] ServiceAccount:shop/default        via default-sa-exec  bound to a namespace's default service account (every pod inherits it)
who can get secrets: ['Group:system:unauthenticated', 'ServiceAccount:ci-runner']
who can create pods/exec: ['ServiceAccount:ci-runner', 'ServiceAccount:default']
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# KubiScan (verify maintenance first); it reads from a cluster you are authorized to inspect
python3 KubiScan.py -rs            # risky subjects (check the README for exact flags)
# Maintained alternatives
kubectl who-can get secrets -n <ns>
rbac-tool who-can get secrets
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubescape scan framework nsa            # includes RBAC-related controls (verify framework names)
```
Run only against clusters you own and use a read-only kubeconfig.
