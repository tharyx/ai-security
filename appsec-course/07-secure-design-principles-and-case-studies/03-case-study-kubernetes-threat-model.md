# Lesson 03: Case Study: Kubernetes Threat Model

**Syllabus item covered:** [CTMP 5] "Case Study of Kubernetes Threat Model".

**Time:** 1.5 hours plus lab. **Safety:** manifests are JSON fixtures; no cluster is needed or touched.

> **DBA analogy.** The Kubernetes API server is the database listener plus the data dictionary: whoever can talk to it with enough privilege controls everything. etcd is the SYSTEM tablespace. A pod with `hostPath: /` is a user who can read the datafiles directly, bypassing every grant.

## 1. Sources

- **2019 Kubernetes security audit** commissioned by the CNCF (performed by Trail of Bits and Atredis Partners): a threat model of the control plane and components, plus findings. It popularised the component-level DFD and trust-boundary view of Kubernetes.
- **2022 re-audit** (NCC Group, for the CNCF; verify) and its follow-ups.
- **CNCF TAG Security** papers (Cloud Native Security Whitepaper, threat modeling guidance) and the **Kubernetes SIG Security** work.
- **Microsoft's Threat Matrix for Kubernetes** (ATT&CK-style), **MITRE ATT&CK Containers** matrix, **OWASP Kubernetes Top 10**, and the **CIS Kubernetes Benchmark**. Verify current versions.

## 2. DFD and trust boundaries

```text
[Users, CI/CD] --kubectl/HTTPS--> (kube-apiserver) <--> [etcd]
(kube-apiserver) <--> (controller-manager, scheduler)
(kube-apiserver) <--> (kubelet on each node) --> (container runtime) --> [pods]
[pods] --service account token--> (kube-apiserver)
[Internet] --> (ingress / load balancer) --> [pods]
Trust boundaries: Internet | cluster network | node (host) | container | control plane
```

The key boundaries: **container → node** (escape), **pod → API server** (service account abuse), **namespace → namespace** (lateral movement), **cluster → cloud account** (node or workload identity), and **supply chain → cluster** (images).

## 3. Threat table (ids match the lab where checked)

| Id | STRIDE | Threat | Mitigation |
|---|---|---|---|
| K8S-T1 | Elevation of Privilege | Pod shares the host network, PID or IPC namespace | `hostNetwork/hostPID/hostIPC: false`; Pod Security Standards |
| K8S-T2 | Elevation of Privilege | `hostPath` volume (for example the container runtime socket) gives node control | No hostPath; restricted profile |
| K8S-T3 | Spoofing / EoP | Stolen service account token from a compromised pod | `automountServiceAccountToken: false`; bound, short-lived tokens; minimal RBAC |
| K8S-T4 | Elevation of Privilege | Privileged container, privilege escalation, extra capabilities | `privileged: false`, `allowPrivilegeEscalation: false`, drop ALL capabilities, seccomp RuntimeDefault |
| K8S-T5 | Tampering / EoP | Root user and writable filesystem make exploitation easier | `runAsNonRoot`, `readOnlyRootFilesystem` |
| K8S-T6 | Tampering | Mutable or unverified images (`:latest`, typosquats) | Pin by digest, signed images (Sigstore), admission policy |
| K8S-T7 | Denial of Service | No resource limits; one pod starves the node | Requests/limits, LimitRange, ResourceQuota |
| K8S-T8 | Information Disclosure | Secrets as literal env values in manifests and git | `secretKeyRef`, external secrets/vault, etcd encryption at rest |
| K8S-T9 | Elevation of Privilege | Namespace allows privileged pods | Pod Security Admission `enforce: restricted` |
| K8S-T10 | Elevation of Privilege | RBAC wildcards (`*` verbs/resources) | Least-privilege Roles, namespace-scoped |
| K8S-T11 | Spoofing / Information Disclosure | Bindings to `system:anonymous` / `system:unauthenticated` | No anonymous bindings; `--anonymous-auth=false` where possible |
| K8S-T12 | Lateral movement (EoP / Info Disclosure) | Flat pod network | Default-deny NetworkPolicy per namespace, then allow lists |
| K8S-T13 | Information Disclosure | etcd reachable or unencrypted | etcd TLS + client auth, encryption at rest, network isolation |
| K8S-T14 | Spoofing | Kubelet API reachable without authentication | Kubelet authn/authz webhook, no read-only port |
| K8S-T15 | Repudiation | No audit logs of API actions | API server audit policy, ship logs to SIEM |

## 4. Principles in this case

- **Least privilege:** RBAC, service accounts, capabilities, non-root.
- **Fail-safe defaults:** default-deny NetworkPolicy, Pod Security Admission restricted (note that Kubernetes defaults are often permissive, so you must set them).
- **Complete mediation:** admission controllers on every create/update; API server authorization on every request.
- **Least common mechanism:** namespaces, separate node pools for sensitive workloads, no shared service accounts.
- **Economy of mechanism:** fewer cluster-admin paths, fewer custom admission webhooks.

## 5. Scenario

A team's CI job deployed with a ClusterRole that had `*` on `*` "to make it work". An attacker who stole the CI token created a privileged pod with `hostPath: /` in a namespace without Pod Security Admission, read the node's kubelet credentials and cloud metadata, and moved to the cloud account. Four controls from the table (K8S-T10, T9, T2/T4, plus blocking metadata access) would each have broken the chain.

## 6. Lab

The [cloud-native-threat-model-checks lab](labs/cloud-native-threat-model-checks/README.md) checks Namespace, Deployment, NetworkPolicy, Role and binding fixtures against K8S-T1 to K8S-T12. Container security in depth: [devsecops-course chapter 11](../../devsecops-course/11-defending-containers-at-scale/README.md).

## References

- CNCF Kubernetes security audit (2019) and threat model; 2022 re-audit; CNCF TAG Security Cloud Native Security Whitepaper (verify).
- Kubernetes documentation: Pod Security Standards and Admission, RBAC good practices, Network Policies, Securing a Cluster.
- Microsoft Threat Matrix for Kubernetes; MITRE ATT&CK Containers; OWASP Kubernetes Top 10; CIS Kubernetes Benchmark.
- Repo: [devsecops-course chapter 10 container attacks](../../devsecops-course/10-container-reconnaissance-and-attacks/README.md).
