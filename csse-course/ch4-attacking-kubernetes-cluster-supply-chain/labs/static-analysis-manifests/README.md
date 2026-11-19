# Lab: Static analysis of Kubernetes manifests (plus Helm chart rendering and webhook audit)

**Course exercise:** "Static analysis of Kubernetes manifests". Lessons: [02](../../02-supply-chain-threats-for-a-cluster-helm.md), [03 section 3](../../03-abusing-the-kubernetes-request-pipeline.md#3-attacks-on-admission-controllers-and-webhooks), [05 section 2](../../05-securing-container-orchestration.md#2-static-analysis-of-kubernetes-clusters).

**Time:** 90 minutes. **Safety:** everything is read-only text analysis. The chart's hook runs only `echo SIMULATED migration step` and is never executed.

## Three tools in one lab

1. **Manifest checker (reused):** [06-ai-devsecops/kubernetes/lab/k8s_policy.py](../../../../06-ai-devsecops/kubernetes/lab/k8s_policy.py) (17 rules: privileged, root, hostPath, secrets in env, RBAC, network, Pod Security labels, and more; see its [README](../../../../06-ai-devsecops/kubernetes/README.md)). Loaded by path, not copied.
2. **Helm render + chart checks:** [helm_render.py](helm_render.py) is a small template engine (values, `quote`, `default`, `upper`, `if/else/end`; no Sprig, `range`, `with`, `include`). [static_check.py](static_check.py) renders the chart under given values, runs the manifest checker on the **rendered** objects, and adds `HELM-001` to `HELM-009`.
3. **Admission webhook audit:** [webhook_audit.py](webhook_audit.py) reports `WH-001` to `WH-008` and simulates a bypass.

## The fixture chart (deliberately bad)

`fixtures/chart/` has insecure default values (`privileged: true`, tag `latest`, LoadBalancer), a cluster-admin binding, a privileged `pre-install` hook, an HTTP dependency repository, no `Chart.lock`, no `.prov` file. `values-secure.yaml` fixes the workload side.

| ID | Finding |
|---|---|
| HELM-001 to HELM-003 | dependency repo over HTTP or untrusted; version ranges; no lock file |
| HELM-004 | no provenance (`.prov`) file |
| HELM-005, HELM-006 | `latest` tag and privileged defaults in values |
| HELM-007 | hook runs privileged or on the host network |
| HELM-008 | chart installs a cluster-admin binding |
| HELM-009 | template uses `lookup` |

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/static-analysis-manifests/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/static-analysis-manifests -v
```

1. Fix `fixtures/manifests/bad-deployment.yaml` until the checker reports no high or critical findings.
2. Compare the chart's default values and `values-secure.yaml`. Which findings remain? (Chart-level supply chain ones: unsigned, unlocked, HTTP repo.)
3. Fix the webhook file: `failurePolicy: Fail`, HTTPS or in-cluster service with `caBundle`, short timeout, exclusion by namespace name only.

## Expected output (real run, abridged)

```text
== Helm chart, default values ==
  [HIGH    ] HELM-001 dependency redis: repository http://charts.sketchy.example uses plain HTTP: tampering in transit
  [HIGH    ] HELM-007 Job/demo-migrate: hook pre-install,pre-upgrade runs privileged or on the host network during install/upgrade
  [CRITICAL] HELM-008 ClusterRoleBinding/demo-admin: chart installs a cluster-admin binding
== admission webhooks ==
  [HIGH    ] WH-001 ... failurePolicy Ignore: if the webhook is down, slow or crashed, requests are admitted unchecked ...
  [CRITICAL] WH-003 ... webhook called over plain HTTP ...
pod in exempt namespace : ADMIT (namespace is exempt: webhook never called)
webhook outage          : ADMIT (failurePolicy Ignore, webhook unreachable)
same outage, Fail policy: REJECT (failurePolicy Fail, webhook unreachable)
```

## Real tools

`helm lint`, `helm template | kubeconform`, kube-linter, Kubescape, `trivy config`, Checkov, Polaris; `helm verify` for `.prov` files; cosign for OCI charts. See [real-tools/helm-4.md](../../real-tools/helm-4.md).
