# Lesson 05: Technologies and Solutions for Securing Container Orchestration

> **Chapter:** 4 · Attacking the Kubernetes Cluster Supply Chain · **Time:** ~5 hours
> **You will:** apply static analysis to manifests, charts and clusters, and explain dynamic analysis and runtime security (Falco, Tetragon concepts, audit logs).

| | |
|---|---|
| **Prerequisites** | [Lessons 01 to 04](01-microservices-and-kubernetes.md) |
| **Labs** | [static-analysis-manifests](labs/static-analysis-manifests/README.md) · [k8s-image-scanning](labs/k8s-image-scanning/README.md) · [privileged-pods](labs/privileged-pods/README.md) · [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) |
| **Syllabus lines** | Technologies and solutions for securing container orchestration · Static analysis of Kubernetes clusters · Dynamic analysis and runtime security of Kubernetes clusters |
| **Maps to** | CIS Kubernetes Benchmark · NSA/CISA Kubernetes Hardening Guide · NIST SP 800-190 · Pod Security Standards |

## 1. Why it matters

Prevention (policy before deploy) and detection (alerts at run time) are different jobs. Static analysis finds mistakes before they reach the cluster. Runtime security finds what slipped through, or what was never a misconfiguration at all (a stolen token being used).

## 2. Static analysis of Kubernetes clusters

"Static" means analysing **configuration** without running attacks: manifests in Git, Helm charts (rendered), the live objects in a cluster, and the cluster components' settings.

| Target | What to check | Tools |
|---|---|---|
| **Manifests and rendered charts** (shift left, in CI) | Pod security context, privileged, hostPath, image tags and digests, resource limits, secrets in plain text, RBAC wildcards, NetworkPolicy presence | **kube-linter**, **Kubescape**, **Trivy** (`trivy config`), Checkov, Polaris, kubeconform (schema). Offline twin: [k8s_policy](../../06-ai-devsecops/kubernetes/README.md) + [static-analysis lab](labs/static-analysis-manifests/README.md) |
| **Images** | Known vulnerabilities, secrets, misconfiguration, SBOM | Trivy, Grype, Snyk, Harbor scanner. Offline twin: [k8s-image-scanning](labs/k8s-image-scanning/README.md) |
| **Live cluster posture** | Same checks on running objects, plus RBAC and network exposure | `trivy k8s`, Kubescape, Kyverno policy reports |
| **Cluster components (CIS Benchmark)** | API server flags, kubelet config, etcd, file permissions | **kube-bench** (CIS), managed-service equivalents |
| **RBAC** | Risky roles and bindings, who-can questions | Kubescape, rbac-tool, kubectl-who-can (check KubiScan maintenance before use) |
| **Policy as code** | Enforce rules at admission | Pod Security Admission, ValidatingAdmissionPolicy (CEL), **Kyverno**, **OPA Gatekeeper** |
| **Attack path modelling** | Which misconfigurations chain into a breach | Kubescape and commercial platforms; the [stealing-k8s-secrets lab](labs/stealing-k8s-secrets/README.md) shows the idea |

**A good pipeline:** `helm template` or `kustomize build` → schema check (kubeconform) → policy scan (Kubescape or Trivy config) → image scan → sign → deploy through GitOps → **admission policy re-checks** (because CI can be skipped) → posture scans on a schedule.

### 2.1 Policy as code at admission

```yaml
# ValidatingAdmissionPolicy (CEL): deny containers without a digest
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: require-image-digest}
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - {apiGroups: [""], apiVersions: ["v1"], operations: ["CREATE", "UPDATE"], resources: ["pods"]}
  validations:
    - expression: "object.spec.containers.all(c, c.image.contains('@sha256:'))"
      message: "images must be pinned by digest"
```

(A binding object, `ValidatingAdmissionPolicyBinding`, applies it to namespaces. Check your version's API and examples at kubernetes.io; the lab keeps policies offline.) Kyverno and Gatekeeper offer richer libraries, mutation and image-signature verification.

## 3. Dynamic analysis and runtime security

"Dynamic" means looking at **behaviour while running**: what processes start, which files are touched, which connections are made, which API calls happen.

### 3.1 What to watch

| Signal | Example detection |
|---|---|
| **Process** | A shell spawned in a web container; a package manager run in production; a known mining binary |
| **File** | Read of `/var/run/secrets/kubernetes.io/serviceaccount/token` by an unexpected process; writes under `/etc`, `/usr/bin` |
| **Network** | Outbound connection from a database pod; call to the cloud metadata IP; connection to the kubelet port |
| **Kernel** | Loading a kernel module; `ptrace`; mount; unexpected `setns` |
| **Kubernetes API** (audit log) | `pods/exec` by a user at 3 a.m.; new ClusterRoleBinding; new webhook configuration; `list secrets` by a workload |
| **Admission** | Spike in denials, or a webhook error (a possible bypass attempt) |

### 3.2 Tools and concepts

- **Falco** (CNCF): rule-based runtime detection. A sensor (eBPF-based driver) sees system calls and Kubernetes metadata, and rules like "shell in container" raise alerts. Rules can be tuned; outputs go to SIEM, Slack or a response engine.
- **Tetragon** (Cilium/Isovalent, eBPF): runtime observability **and enforcement**: policies (`TracingPolicy`) can observe and also block or kill actions in the kernel path (check supported actions in your version).
- **Other:** KubeArmor, Tracee (Aqua), commercial CNAPP and EDR products, Kubernetes audit logs plus a SIEM.
- **Network visibility:** Cilium Hubble or flow logs; NetworkPolicy and mesh telemetry.
- **Response:** isolate a pod with a quarantine NetworkPolicy, kill and replace it (it is cattle), rotate the token or secret it could reach, preserve evidence first.

Sketch of a Falco-style rule (concept, not a drop-in; verify syntax against your Falco version):

```yaml
- rule: Terminal shell in container
  desc: A shell was started with an attached terminal in a container
  condition: spawned_process and container and shell_procs and proc.tty != 0
  output: "Shell in container (user=%user.name container=%container.name image=%container.image.repository cmd=%proc.cmdline)"
  priority: NOTICE
```

### 3.3 Dynamic analysis in testing

Authorised tests exercise the cluster: DAST on exposed services, chaos or attack simulation tools, and purple-team replay of matrix techniques. Keep them in test clusters.

## 4. Static versus dynamic

| | Static | Dynamic / runtime |
|---|---|---|
| Finds | Misconfiguration, known vulnerable images, risky RBAC | Active exploitation, token abuse, zero-days' behaviour, insider actions |
| When | Before deploy and on a schedule | Continuously |
| False positives | Moderate (context missing) | Noise until tuned |
| Needs | Manifests, API read access | Sensors (eBPF), logs, tuning, on-call |
| Weakness | Cannot see what the app does | Cannot prevent what it does not detect; needs response |

Use both. They cover each other's gaps.

## 5. Defend: a minimum programme

1. CI scans (manifests, charts, images) and a signature policy at admission.
2. Pod Security Admission `restricted` on workload namespaces; default-deny NetworkPolicy.
3. API audit logging shipped to a SIEM, with alerts for RBAC and webhook changes, `pods/exec`, and secrets list.
4. Runtime detection (Falco or Tetragon) with a tuned rule set and a response runbook.
5. Regular CIS (kube-bench) and posture scans; patch the cluster.
6. Practice: an incident drill that follows the threat-matrix chain.

## 6. Hands-on

1. Run the [static-analysis-manifests lab](labs/static-analysis-manifests/README.md): fix every high finding in `bad-deployment.yaml`.
2. Run the [image-scanning lab](labs/k8s-image-scanning/README.md) and make the gate pass by pinning digests and updating image entries.
3. Read [real-tools/falco.md](real-tools/falco.md) and write two Falco-style rule descriptions for your own cluster (shell in container; token read by a non-app process).

## 7. Scenario

Your cluster shows a Falco alert "Read of service account token by process `curl`" in the `web` pod at 02:14, followed by `pods/create` API calls from the `web` service account. Describe the response steps: confirm via audit log, isolate the pod, rotate and revoke the token, inspect created pods and RBAC, find the initial vulnerability, patch, and write a detection improvement.

## 8. Interview Q&A

<details>
<summary>What is the difference between static and dynamic analysis for Kubernetes?</summary>

Static analysis checks configuration (manifests, charts, RBAC, images) without running attacks, typically before deploy. Dynamic or runtime analysis observes behaviour of running workloads and the API (processes, files, network, audit events) to detect attacks.
</details>

<details>
<summary>Name two runtime security tools and how they differ.</summary>

Falco detects and alerts based on rules over syscalls and Kubernetes metadata. Tetragon (Cilium) also uses eBPF and can enforce policy in the kernel path (block or kill), not just observe. Both are CNCF-ecosystem projects (verify current status).
</details>

<details>
<summary>kube-hunter is legacy. How do you scan a cluster today?</summary>

`trivy k8s` or Kubescape for misconfiguration, vulnerabilities and RBAC; kube-bench for CIS node and control-plane checks; plus authorised penetration testing.
</details>

<details>
<summary>Why enforce policy at admission if CI already scans?</summary>

CI can be bypassed (manual kubectl, a different pipeline, a compromised credential). Admission is the last gate before objects exist, so it protects every path.
</details>

## 9. References

- Kubernetes docs: Pod Security Standards, ValidatingAdmissionPolicy, Auditing (verify). CIS Kubernetes Benchmark. NSA/CISA Kubernetes Hardening Guide.
- Falco docs; Tetragon docs; Kubescape docs; Trivy docs.
- Repo: [06 runtime security](../../06-ai-devsecops/runtime-security/README.md), [06 Kubernetes](../../06-ai-devsecops/kubernetes/README.md).
