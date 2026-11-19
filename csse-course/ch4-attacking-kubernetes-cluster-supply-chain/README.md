# Chapter 4: Attacking the Kubernetes Cluster Supply Chain

This chapter covers **Kubernetes as the place where your supply chain lands**: microservices and cluster architecture, Helm and other package risks, abuse of the API request pipeline (authentication, authorization, admission, webhooks, RBAC), common attack vectors, and static and runtime defences. Twelve labs (plus a webhook audit) run offline with manifest and fixture simulations: **no cluster is required**.

> **Safety.** Every lab is a simulation: YAML/JSON fixtures, in-process "servers", FAKE credentials, `.example` names and RFC 5737 documentation IPs. Nothing is applied to a cluster, scanned, or sent over a network. Never scan or probe clusters you do not own or are not authorised to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers here are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Microservices and Kubernetes | [Lesson 01](01-microservices-and-kubernetes.md) | n/a |
| Introduction to Microservices Architecture | [01 section 2](01-microservices-and-kubernetes.md#2-introduction-to-microservices-architecture) | [working-with-kubernetes](labs/working-with-kubernetes/README.md) |
| Introduction to Kubernetes Architecture | [01 section 3](01-microservices-and-kubernetes.md#3-introduction-to-kubernetes-architecture) (SVG); repo [06 Kubernetes](../../06-ai-devsecops/kubernetes/README.md) | [k8s-basic-commands](labs/k8s-basic-commands/README.md) |
| Core Components of Kubernetes | [01 section 4](01-microservices-and-kubernetes.md#4-core-components-of-kubernetes) | [k8s-basic-commands](labs/k8s-basic-commands/README.md), [working-with-kubernetes](labs/working-with-kubernetes/README.md) |
| Supply Chain Threats for a cluster | [Lesson 02](02-supply-chain-threats-for-a-cluster-helm.md) | n/a |
| Kubernetes Package Manager | [02 section 2](02-supply-chain-threats-for-a-cluster-helm.md#2-kubernetes-package-manager) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) |
| Helm and its security | [02 section 3](02-supply-chain-threats-for-a-cluster-helm.md#3-helm-and-its-security) and [section 6](02-supply-chain-threats-for-a-cluster-helm.md#6-helm-chart-risks-attack-view) (Helm 4); [real-tools/helm-4.md](real-tools/helm-4.md) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) |
| Understanding Helm charts workflow | [02 section 4](02-supply-chain-threats-for-a-cluster-helm.md#4-understanding-the-helm-chart-workflow) (SVG) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) |
| Creating Helm Charts | [02 section 5](02-supply-chain-threats-for-a-cluster-helm.md#5-creating-helm-charts) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) (fixture chart + renderer) |
| Abusing Kubernetes Request Pipeline | [Lesson 03](03-abusing-the-kubernetes-request-pipeline.md) | n/a |
| Authentication, Authorization, and Admission Controllers | [03 section 2](03-abusing-the-kubernetes-request-pipeline.md#2-authentication-authorization-and-admission-controllers) (SVG; PSP removed in 1.25) | [privileged-pods](labs/privileged-pods/README.md), [service-accounts](labs/service-accounts/README.md) |
| Attacks on Admission Controllers and webhooks | [03 section 3](03-abusing-the-kubernetes-request-pipeline.md#3-attacks-on-admission-controllers-and-webhooks) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) (webhook audit and bypass simulation) |
| Insecure RBAC rules | [03 section 4](03-abusing-the-kubernetes-request-pipeline.md#4-insecure-rbac-rules) | [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) |
| Common Attack Vectors in Kubernetes Clusters | [Lesson 04](04-common-attack-vectors-in-kubernetes-clusters.md) (Threat Matrix for Kubernetes) | [kube-hunter-recon](labs/kube-hunter-recon/README.md), [kubelet-api](labs/kubelet-api/README.md), [privileged-pods](labs/privileged-pods/README.md), [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) |
| Technologies and solutions for securing container orchestration | [Lesson 05](05-securing-container-orchestration.md) | n/a |
| Static analysis of Kubernetes clusters | [05 section 2](05-securing-container-orchestration.md#2-static-analysis-of-kubernetes-clusters); [real-tools/kubescape.md](real-tools/kubescape.md), [real-tools/trivy-k8s.md](real-tools/trivy-k8s.md) | [static-analysis-manifests](labs/static-analysis-manifests/README.md), [k8s-image-scanning](labs/k8s-image-scanning/README.md) |
| Dynamic analysis and runtime security of Kubernetes clusters | [05 section 3](05-securing-container-orchestration.md#3-dynamic-analysis-and-runtime-security) (Falco, Tetragon); [real-tools/falco.md](real-tools/falco.md); repo [06 runtime security](../../06-ai-devsecops/runtime-security/README.md) | [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md), [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) |
| Hands-On Exercises: | Labs below | [Lab index](#lab-index) |
| Kubernetes basic commands | [CHEATSHEET.md](labs/k8s-basic-commands/CHEATSHEET.md); [01](01-microservices-and-kubernetes.md) | [k8s-basic-commands](labs/k8s-basic-commands/README.md) |
| Working with Kubernetes | [01 section 4.3](01-microservices-and-kubernetes.md#43-objects-you-will-see) | [working-with-kubernetes](labs/working-with-kubernetes/README.md) |
| Kubernetes secrets | [01](01-microservices-and-kubernetes.md), [04 section 3.3](04-common-attack-vectors-in-kubernetes-clusters.md#33-secrets-exposure) | [k8s-secrets](labs/k8s-secrets/README.md) |
| Kubernetes service accounts | [03 section 2.1](03-abusing-the-kubernetes-request-pipeline.md#21-authentication-who-are-you), [04 section 3.2](04-common-attack-vectors-in-kubernetes-clusters.md#32-compromised-pod-and-stolen-service-account-token) | [service-accounts](labs/service-accounts/README.md) |
| Kubernetes networking using Calico | [01 section 4.3](01-microservices-and-kubernetes.md#43-objects-you-will-see), [04 section 3.5](04-common-attack-vectors-in-kubernetes-clusters.md#35-flat-networks-and-plaintext-traffic) | [calico-networking](labs/calico-networking/README.md) |
| Reconnaissance using Kube-hunter | [04 sections 3.1 and 5](04-common-attack-vectors-in-kubernetes-clusters.md#5-recon-tools-legacy-versus-current) (kube-hunter is legacy; use `trivy k8s` / Kubescape) | [kube-hunter-recon](labs/kube-hunter-recon/README.md) |
| Stealing Kubernetes secrets | [03 section 4](03-abusing-the-kubernetes-request-pipeline.md#4-insecure-rbac-rules), [04 section 3.2](04-common-attack-vectors-in-kubernetes-clusters.md#32-compromised-pod-and-stolen-service-account-token) | [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) |
| Exploiting Kubelet API | [01 section 4.2](01-microservices-and-kubernetes.md#42-node-components), [04 section 3.1](04-common-attack-vectors-in-kubernetes-clusters.md#31-exposed-control-plane-and-node-endpoints) | [kubelet-api](labs/kubelet-api/README.md) |
| Privileged pods in Kubernetes | [03 section 2.3](03-abusing-the-kubernetes-request-pipeline.md#23-admission-control-is-this-object-acceptable), [04 section 3.4](04-common-attack-vectors-in-kubernetes-clusters.md#34-privileged-and-over-powerful-pods) | [privileged-pods](labs/privileged-pods/README.md) |
| Sniffing Kubernetes network traffic | [04 section 3.5](04-common-attack-vectors-in-kubernetes-clusters.md#35-flat-networks-and-plaintext-traffic) | [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) |
| Kubernetes image scanning | [05 section 2](05-securing-container-orchestration.md#2-static-analysis-of-kubernetes-clusters); [chapter 3 Trivy guide](../ch3-attacking-container-supply-chain/real-tools/trivy.md) | [k8s-image-scanning](labs/k8s-image-scanning/README.md) |
| Static analysis of Kubernetes manifests | [05 section 2](05-securing-container-orchestration.md#2-static-analysis-of-kubernetes-clusters); repo [06 Kubernetes](../../06-ai-devsecops/kubernetes/README.md) | [static-analysis-manifests](labs/static-analysis-manifests/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Reconnaissance using Kube-hunter** | kube-hunter (Aqua Security) is **no longer actively developed**; Aqua recommends **Trivy** (`trivy k8s`) for cluster scanning. Use `trivy k8s`, **Kubescape** (CNCF) and **kube-bench**. The recon *ideas* in the lab still apply. |
| **Admission controllers** (and older PSP tutorials) | **PodSecurityPolicy was removed in Kubernetes 1.25** (2022). Use **Pod Security Admission**, **ValidatingAdmissionPolicy** (CEL), **Kyverno** or **OPA Gatekeeper**. |
| **Helm and its security** (Helm 2, Tiller) | Tiller is gone (Helm 3, 2019). **Helm 4** was released **12 Nov 2025** (WASM plugin system, server-side apply by default; verify). Helm 3 security fixes continue until roughly early 2027 (verify). |
| **Kubernetes networking using Calico** | Calico is still current, but also look at **Cilium** (eBPF, Hubble, mesh). Many cluster CNIs differ in NetworkPolicy features. kind's default CNI does not enforce NetworkPolicy. |
| **Service accounts** | Modern clusters use **bound, projected tokens** (audience, expiry, pod-bound). Secret-based long-lived tokens are no longer auto-created; do not create them. |
| **Dynamic analysis and runtime security** | Falco remains central; **Tetragon** (eBPF, can enforce) and KubeArmor are widely discussed. Check each project's current status. |
| **Common attack vectors** | Use Microsoft's **Threat Matrix for Kubernetes** and MITRE ATT&CK for Containers; both have been revised since the first versions (verify). |
| **Tools unnamed in the syllabus** | KubiScan, Tern, packj and similar projects have uncertain maintenance: check each repo before relying on it. Current RBAC options: kubectl-who-can, rbac-tool, Kubescape. |

## Learning order

1. [Lesson 01](01-microservices-and-kubernetes.md), then [k8s-basic-commands](labs/k8s-basic-commands/README.md) and [working-with-kubernetes](labs/working-with-kubernetes/README.md). About 5 hours.
2. [k8s-secrets](labs/k8s-secrets/README.md), [service-accounts](labs/service-accounts/README.md), [calico-networking](labs/calico-networking/README.md). About 5 hours.
3. [Lesson 02](02-supply-chain-threats-for-a-cluster-helm.md) and [static-analysis-manifests](labs/static-analysis-manifests/README.md) (chart part). About 5 hours.
4. [Lesson 03](03-abusing-the-kubernetes-request-pipeline.md), then [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md), [privileged-pods](labs/privileged-pods/README.md) and the webhook audit. About 7 hours.
5. [Lesson 04](04-common-attack-vectors-in-kubernetes-clusters.md), then [kube-hunter-recon](labs/kube-hunter-recon/README.md), [kubelet-api](labs/kubelet-api/README.md), [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md). About 6 hours.
6. [Lesson 05](05-securing-container-orchestration.md), then [k8s-image-scanning](labs/k8s-image-scanning/README.md) and the [real-tools guides](real-tools/). About 5 hours.
7. Then [Chapter 5](../ch5-attacking-cloud-supply-chain/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain`.

| Lab | Course exercise | Tests |
|---|---|---|
| [k8s-basic-commands](labs/k8s-basic-commands/README.md) | Kubernetes basic commands | 7 |
| [working-with-kubernetes](labs/working-with-kubernetes/README.md) | Working with Kubernetes | 8 |
| [k8s-secrets](labs/k8s-secrets/README.md) | Kubernetes secrets | 10 |
| [service-accounts](labs/service-accounts/README.md) | Kubernetes service accounts | 10 |
| [calico-networking](labs/calico-networking/README.md) | Kubernetes networking using Calico | 10 |
| [kube-hunter-recon](labs/kube-hunter-recon/README.md) | Reconnaissance using Kube-hunter | 10 |
| [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) | Stealing Kubernetes secrets | 9 |
| [kubelet-api](labs/kubelet-api/README.md) | Exploiting Kubelet API | 9 |
| [privileged-pods](labs/privileged-pods/README.md) | Privileged pods in Kubernetes | 10 |
| [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) | Sniffing Kubernetes network traffic | 9 |
| [k8s-image-scanning](labs/k8s-image-scanning/README.md) | Kubernetes image scanning | 9 |
| [static-analysis-manifests](labs/static-analysis-manifests/README.md) | Static analysis of Kubernetes manifests (+ Helm render, webhook audit) | 13 |

Hedged guides for real tools: [kind and minikube](real-tools/kind-minikube.md), [Helm 4](real-tools/helm-4.md), [Kubescape](real-tools/kubescape.md), [trivy k8s](real-tools/trivy-k8s.md), [Falco](real-tools/falco.md). Chapter 3 also has [Docker](../ch3-attacking-container-supply-chain/real-tools/docker.md), [Trivy](../ch3-attacking-container-supply-chain/real-tools/trivy.md) and [cosign/Notation](../ch3-attacking-container-supply-chain/real-tools/cosign-notation.md).

## Exam tips

- **Request pipeline order:** authentication, authorization, mutating admission, schema validation, validating admission, etcd.
- **PSP is gone** (1.25). Say Pod Security Admission with its three levels (privileged, baseline, restricted), ValidatingAdmissionPolicy, Kyverno, Gatekeeper.
- **Webhooks:** `failurePolicy: Ignore` plus an outage equals a bypass. A malicious mutating webhook rewrites objects before validation.
- **RBAC red flags:** wildcards, `list/watch secrets`, `create pods`, `pods/exec`, `nodes/proxy`, `escalate`, `bind`, `impersonate`, cluster-admin for apps.
- **Secrets:** base64 is encoding. Encrypt etcd (KMS v2 preferred), avoid env vars, narrow RBAC.
- **Tokens:** automount off, bound tokens with audience and expiry.
- **NetworkPolicy:** default deny, both ends must allow, the CNI must enforce policy.
- **Helm:** no Tiller since v3; Helm 4 (Nov 2025). Scan rendered output; verify provenance; watch hooks, values and third-party repos.
- **kube-hunter is legacy:** `trivy k8s`, Kubescape, kube-bench.
- **Static plus runtime:** both are needed; admission is the last gate; Falco detects, Tetragon can enforce.

## 15 exam-style questions

<details>
<summary>1. Why are microservices a security challenge?</summary>

Many small services mean many images, identities, secrets and network paths. In-process calls become network calls that must be authenticated and encrypted, and a flat default network lets one compromised service reach the others.
</details>

<details>
<summary>2. Name the control-plane and node components and one security setting for each.</summary>

kube-apiserver (authn/authz/admission/audit), etcd (client certs and encryption at rest), scheduler and controller-manager (protect credentials), kubelet (anonymous auth off, Webhook authorization, no read-only port), container runtime (patch runc/containerd), CNI (NetworkPolicy support).
</details>

<details>
<summary>3. What is the order of the API request pipeline?</summary>

Authentication, authorization, mutating admission, schema validation, validating admission, persistence in etcd.
</details>

<details>
<summary>4. What replaced PodSecurityPolicy?</summary>

PSP was removed in Kubernetes 1.25. Use Pod Security Admission (namespace labels, three levels), ValidatingAdmissionPolicy (CEL) and policy engines such as Kyverno or OPA Gatekeeper.
</details>

<details>
<summary>5. How can an admission webhook be bypassed or abused?</summary>

`failurePolicy: Ignore` with a webhook outage or DoS, namespace exemptions by label, rules that miss operations or resources, long timeouts, plain-HTTP or unpinned endpoints, and a malicious or compromised mutating webhook that rewrites objects. Also persistence by creating a webhook configuration.
</details>

<details>
<summary>6. Which RBAC permissions give access to secrets, even without "get secrets"?</summary>

`list`/`watch` secrets (return all values), `create pods` (mount a Secret), `pods/exec` (read from a pod), `serviceaccounts/token`, `impersonate`, `nodes/proxy`, `escalate`/`bind`, patching workloads, and wildcards.
</details>

<details>
<summary>7. base64 in a Secret: is it encrypted?</summary>

No, it is encoding. Anyone with read access decodes it. Use encryption at rest (KMS v2 preferred), narrow RBAC and external secret managers.
</details>

<details>
<summary>8. What is a bound service-account token?</summary>

A signed JWT with an audience, an expiry and a binding to a specific pod; it stops working when the pod is deleted or the token expires. Legacy Secret-based tokens never expired.
</details>

<details>
<summary>9. How does NetworkPolicy decide whether pod A can reach pod B?</summary>

Both A's egress and B's ingress must allow it. A pod with no policy for a direction is open; once selected by a policy for that direction it is isolated and only allowed traffic passes. Policies are additive. The CNI must enforce them.
</details>

<details>
<summary>10. What did kube-hunter do, and what replaces it?</summary>

It hunted for weaknesses (open API server, kubelet, etcd, dashboard). It is no longer actively developed. Use `trivy k8s`, Kubescape and kube-bench, plus authorised testing.
</details>

<details>
<summary>11. Why is an anonymous kubelet dangerous?</summary>

With anonymous auth and AlwaysAllow, anyone who can reach port 10250 can list pods and run commands in containers. Fix: anonymous off, Webhook authorization, no read-only port, network restrictions.
</details>

<details>
<summary>12. Why does the Pod Security "restricted" level matter?</summary>

It requires non-root, no privilege escalation, dropped capabilities, a seccomp profile and limited volume types, which blocks the common container-escape setups. Enforce with namespace labels.
</details>

<details>
<summary>13. How do you defend against sniffing inside a cluster?</summary>

Encrypt service-to-service traffic with mTLS (service mesh, Cilium encryption or app TLS), enforce STRICT mode, default-deny NetworkPolicy, drop `NET_RAW`, avoid `hostNetwork`. Remember metadata (who talks to whom) remains visible.
</details>

<details>
<summary>14. List Helm chart risks and mitigations.</summary>

Templates that render dangerous objects, insecure default values, hooks that run during install, third-party or HTTP repositories, dependencies without a lock, no provenance. Mitigate by rendering and scanning, verifying provenance (`helm verify` or cosign), pinning versions and digests, reviewing hooks and RBAC, and installing with a scoped identity. Helm 4 was released in Nov 2025; Tiller no longer exists.
</details>

<details>
<summary>15. Compare static and dynamic (runtime) analysis for Kubernetes.</summary>

Static analysis checks manifests, charts, RBAC, images and cluster config before deploy (kube-linter, Kubescape, Trivy). Runtime analysis observes behaviour (Falco, Tetragon, audit logs) to detect active attacks. Use both, plus admission as the last gate.
</details>

## References

- Kubernetes docs: Components, RBAC, Admission Controllers, Pod Security Standards, ValidatingAdmissionPolicy, Network Policies, Auditing (verify at kubernetes.io).
- Helm docs (helm.sh); Helm 4 release notes (verify). Microsoft Threat Matrix for Kubernetes. OWASP Kubernetes Top 10. CIS Kubernetes Benchmark. NSA/CISA Kubernetes Hardening Guide.
- Falco, Tetragon, Kubescape and Trivy documentation.
- Repo: [06 Kubernetes](../../06-ai-devsecops/kubernetes/README.md), [06 runtime security](../../06-ai-devsecops/runtime-security/README.md), [cybersecurity-track cloud security](../../cybersecurity-track/10-cloud-security/README.md), [chapter 3](../ch3-attacking-container-supply-chain/README.md).
