# Lesson 04: Common Attack Vectors in Kubernetes Clusters

> **Chapter:** 4 · Attacking the Kubernetes Cluster Supply Chain · **Time:** ~4 hours
> **You will:** walk a typical attack path from initial access to impact using Microsoft's Threat Matrix for Kubernetes as a map, and match each step to a lab and a control.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-microservices-and-kubernetes.md), [lesson 03](03-abusing-the-kubernetes-request-pipeline.md) |
| **Labs** | [kube-hunter-recon](labs/kube-hunter-recon/README.md) · [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) · [kubelet-api](labs/kubelet-api/README.md) · [privileged-pods](labs/privileged-pods/README.md) · [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) · [k8s-image-scanning](labs/k8s-image-scanning/README.md) |
| **Syllabus lines** | Common Attack Vectors in Kubernetes Clusters |
| **Maps to** | Threat Matrix for Kubernetes (Microsoft; verify the current version) · MITRE ATT&CK for Containers · OWASP Kubernetes Top 10 |

> **Safety.** All labs are simulations. Never scan or probe clusters you do not own or have written permission to test.

## 1. Why it matters

Attackers repeat the same moves. A matrix gives you names for them, so you can build detections and test your coverage.

## 2. The threat matrix as a map

Microsoft published a **Threat Matrix for Kubernetes** (inspired by MITRE ATT&CK) with tactics such as the ones below. Names and techniques have been revised since the first version, so treat this table as a teaching summary and check the current matrix and MITRE ATT&CK for Containers.

| Tactic | Typical techniques in clusters | Lab | Main control |
|---|---|---|---|
| **Initial access** | Exposed API server or dashboard; exposed kubelet; compromised cloud credentials or kubeconfig; **vulnerable application in a pod**; **malicious or vulnerable image from a registry** ([chapter 3](../ch3-attacking-container-supply-chain/README.md)); compromised CI/CD or Helm chart | [kube-hunter-recon](labs/kube-hunter-recon/README.md) | Private endpoints, auth on everything, image signing and scanning |
| **Execution** | `exec` into a container; new container (create pod); application exploit; sidecar injection; Kubernetes CronJob | [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md) | RBAC least privilege, admission policy |
| **Persistence** | Backdoor container; writable hostPath; Kubernetes CronJob; malicious admission webhook; new privileged RoleBinding | [static-analysis-manifests](labs/static-analysis-manifests/README.md) (webhook audit) | Audit and alert on RBAC and webhook changes, GitOps drift detection |
| **Privilege escalation** | Privileged container; cluster-admin binding; hostPath mount; access to cloud resources through node or workload identity | [privileged-pods](labs/privileged-pods/README.md) | Pod Security `restricted`, scoped identities |
| **Defense evasion** | Clear container logs; delete events; pod or container name similarity; connect from a proxy | | Central, tamper-evident logging |
| **Credential access** | List Kubernetes secrets; mount service principal or service-account token; access the container service account; **application credentials in configuration files**; access managed identity or cloud metadata | [stealing-k8s-secrets](labs/stealing-k8s-secrets/README.md), [k8s-secrets](labs/k8s-secrets/README.md), [service-accounts](labs/service-accounts/README.md) | No automount, external secrets, metadata endpoint blocking |
| **Discovery** | Access the Kubernetes API server; access the kubelet API; query the Kubernetes Dashboard; network mapping; instance metadata API | [kube-hunter-recon](labs/kube-hunter-recon/README.md), [kubelet-api](labs/kubelet-api/README.md) | NetworkPolicy, authenticated endpoints |
| **Lateral movement** | Access cloud resources; container service account; cluster internal networking (flat pod network); application credentials; writable volume mounts; access the Kubernetes Dashboard | [calico-networking](labs/calico-networking/README.md), [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md) | Default-deny NetworkPolicy, mTLS |
| **Collection / Impact** | Images from a private registry; data destruction; resource hijacking (cryptomining); denial of service | [k8s-image-scanning](labs/k8s-image-scanning/README.md) | Quotas and limits, runtime detection, backups |

## 3. Common vectors, one by one

### 3.1 Exposed control-plane and node endpoints

API server with anonymous access to sensitive paths, **kubelet on 10250 with anonymous-auth** or the read-only port 10255, **etcd without client certs**, an unauthenticated **dashboard**. Detected by recon: [kube-hunter-recon](labs/kube-hunter-recon/README.md) (a legacy tool; see section 5). Fix: private networks, authentication and authorization on every component, CIS benchmark ([kubelet-api lab](labs/kubelet-api/README.md) shows the hardened config).

### 3.2 Compromised pod and stolen service-account token

A bug in an application gives code execution in a pod. The attacker reads `/var/run/secrets/kubernetes.io/serviceaccount/token`, queries the API with it, and uses whatever RBAC it holds. Fix: `automountServiceAccountToken: false`, minimal RBAC, bound tokens, runtime detection of API calls from unexpected pods.

### 3.3 Secrets exposure

Secrets in etcd without encryption, in environment variables, in Git, in Helm release Secrets, or readable through RBAC (`list secrets`). Fix: encryption at rest with KMS, external secret managers, volume mounts instead of env, narrow RBAC ([k8s-secrets](labs/k8s-secrets/README.md)).

### 3.4 Privileged and over-powerful pods

`privileged: true`, `hostPID`, `hostNetwork`, `hostPath`, runtime sockets, extra capabilities. These are container escapes served on a plate. Fix: Pod Security Admission `restricted`; ([privileged-pods](labs/privileged-pods/README.md)).

### 3.5 Flat networks and plaintext traffic

Any pod can reach any pod, the metadata endpoint and the kubelet. A sniffing or lateral-movement foothold sees credentials. Fix: default-deny NetworkPolicy, egress control, mTLS through a service mesh ([calico-networking](labs/calico-networking/README.md), [sniffing-k8s-traffic](labs/sniffing-k8s-traffic/README.md)).

### 3.6 Supply chain entry

Malicious images, unpinned tags, third-party Helm charts, compromised CI. Fix: scan, sign, pin, verify at admission ([k8s-image-scanning](labs/k8s-image-scanning/README.md), [lesson 02](02-supply-chain-threats-for-a-cluster-helm.md)).

### 3.7 Cloud identity bridges

On managed clusters, a pod may reach the cloud metadata service or a node role with broad cloud rights. Fix: workload identity per service account, block the metadata IP for pods (NetworkPolicy or IMDSv2 hop limit), see [chapter 5](../ch5-attacking-cloud-supply-chain/README.md).

## 4. Defend: detect the chain

For each tactic ask: *what log or alert would show this?* Typical sources: **Kubernetes audit logs** (who called the API), **runtime events** (Falco or Tetragon: shell in a container, reading a token, unexpected outbound connection), **network flow logs**, **admission denials**, **cloud audit logs**. See [lesson 05](05-securing-container-orchestration.md) and the cloud detections in [cybersecurity-track CloudTrail](../../cybersecurity-track/10-cloud-security/README.md).

## 5. Recon tools: legacy versus current

**kube-hunter** (Aqua Security) was the classic "hunt for weaknesses" tool with passive and active modes. It is **no longer actively developed**, and Aqua points users to **Trivy** (`trivy k8s`) for cluster scanning. Use `trivy k8s` or **Kubescape** (CNCF) for posture, **kube-bench** for CIS checks, and a proper authorised penetration test for active probing. The recon *questions* remain valid: what ports answer, what answers anonymously, what runs privileged.

## 6. Hands-on

Pick one tactic per day and run its lab; write down the log line that would reveal the step in a real cluster.

## 7. Scenario

A cryptominer is found in a pod in the `shop` namespace. Write the likely chain: vulnerable app in `web` (initial access) → token read (credential access) → pod creation with a miner (execution, impact). Name two preventive and two detective controls.

## 8. Interview Q&A

<details>
<summary>Name five common attack vectors for a Kubernetes cluster.</summary>

Exposed API server, kubelet or dashboard; compromised application pod and stolen service-account token; exposed or over-broad secrets; privileged pods and host mounts; flat network and plaintext traffic; malicious images, charts or CI pipelines.
</details>

<details>
<summary>What is the Threat Matrix for Kubernetes?</summary>

A Microsoft-published ATT&CK-style matrix of tactics and techniques for attacks on Kubernetes (initial access through impact). Check the current version, because the matrix has been updated since the first release.
</details>

<details>
<summary>kube-hunter is mentioned in the course. What would you use now?</summary>

kube-hunter is no longer actively developed. Use `trivy k8s` or Kubescape for posture scanning and kube-bench for CIS checks, plus authorised manual testing.
</details>

## 9. References

- Microsoft Security Blog: Threat Matrix for Kubernetes (verify the current version). MITRE ATT&CK for Containers. OWASP Kubernetes Top 10.
- Kubernetes docs: Auditing. Aqua Security: kube-hunter repository notice (verify).
