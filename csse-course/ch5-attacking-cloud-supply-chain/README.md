# Chapter 5: Attacking the Cloud Supply Chain

This chapter covers how the **cloud** becomes part of the software supply chain: the cloud ecosystem and its shared responsibility model, a threat matrix for cloud attacks, and attack vectors in **AWS, Azure and GCP** (misconfigurations, metadata services, storage and CDN, serverless, deployment services and Kubernetes), ending with cloud security best practices. Five extra labs run fully offline.

> **Safety.** Every lab is a fixture or an in-process simulation: no cloud account, no network, FAKE credentials, `.example` domains. Real-tool commands in the lessons and in [real-tools](real-tools/README.md) are for **your own** accounts only and are hedged: **verify at the provider's documentation**. Never probe buckets, services or clusters you do not own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Service names, defaults and numbers change often.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to Cloud Ecosystem (Public, On-Premise) | [Lesson 01 section 1](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md#1-introduction-to-cloud-ecosystem-public-on-premise); repo [cloud security fundamentals](../../cybersecurity-track/10-cloud-security/01-cloud-security-fundamentals.md) | n/a |
| Cloud Attack Surface and Threat Matrix | [Lesson 01 section 2](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md#2-cloud-attack-surface-and-threat-matrix) (ATT&CK Cloud matrix, Microsoft Threat Matrix for Azure; SVG) | all labs use it as a map |
| Shared Security Model of the Cloud | [Lesson 01 section 3](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md#3-shared-security-model-of-the-cloud); repo [shared responsibility](../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md) | n/a |
| Attack Vectors in AWS | [Lesson 02](02-attack-vectors-in-aws.md); repo [AWS in 09](../../09-enterprise-architecture/02-aws-ai-security.md) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md), [bucket-misconfig](labs/bucket-misconfig/README.md), [serverless-supply-chain](labs/serverless-supply-chain/README.md), [deployment-services](labs/deployment-services/README.md) |
| Misconfigurations (exposed secrets, metadata service, etc.) | [Lesson 02 section 1](02-attack-vectors-in-aws.md#1-misconfigurations-exposed-secrets-metadata-service-etc); repo [cloud identity](../../cybersecurity-track/10-cloud-security/02-cloud-identity.md) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) (IMDSv1 vs IMDSv2), [serverless-supply-chain](labs/serverless-supply-chain/README.md) (env secrets) |
| Attacking Managed Services Like S3, CloudFront CDN | [Lesson 02 section 2](02-attack-vectors-in-aws.md#2-attacking-managed-services-like-s3-cloudfront-cdn) | [bucket-misconfig](labs/bucket-misconfig/README.md) |
| Attacking Serverless Computing | [Lesson 02 section 3](02-attack-vectors-in-aws.md#3-attacking-serverless-computing) | [serverless-supply-chain](labs/serverless-supply-chain/README.md) |
| Attacking Application Deployment Services | [Lesson 02 section 4](02-attack-vectors-in-aws.md#4-attacking-application-deployment-services); repo [06 cicd](../../06-ai-devsecops/cicd/README.md) | [deployment-services](labs/deployment-services/README.md) |
| Attack Vectors in Azure | [Lesson 03](03-attack-vectors-in-azure.md); repo [Azure in 09](../../09-enterprise-architecture/03-azure-ai-security.md) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md), [bucket-misconfig](labs/bucket-misconfig/README.md), [serverless-supply-chain](labs/serverless-supply-chain/README.md), [deployment-services](labs/deployment-services/README.md) |
| Misconfigurations (exposed secrets, metadata services, etc.) | [Lesson 03 section 1](03-attack-vectors-in-azure.md#1-misconfigurations-exposed-secrets-metadata-services-etc) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) (Azure `Metadata: true` header) |
| Attacking Azure Blob storage, Azure Application Gateway | [Lesson 03 section 2](03-attack-vectors-in-azure.md#2-attacking-azure-blob-storage-azure-application-gateway) | [bucket-misconfig](labs/bucket-misconfig/README.md) (Blob containers, SAS) |
| Attacking Azure Functions | [Lesson 03 section 3](03-attack-vectors-in-azure.md#3-attacking-azure-functions) | [serverless-supply-chain](labs/serverless-supply-chain/README.md) |
| Attacking Web Apps | [Lesson 03 section 4](03-attack-vectors-in-azure.md#4-attacking-web-apps) | [deployment-services](labs/deployment-services/README.md) (Azure DevOps connection) |
| Attack Vectors in GCP | [Lesson 04](04-attack-vectors-in-gcp.md); repo [GCP in 09](../../09-enterprise-architecture/04-gcp-ai-security.md) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md), [bucket-misconfig](labs/bucket-misconfig/README.md), [serverless-supply-chain](labs/serverless-supply-chain/README.md), [gke-misconfig](labs/gke-misconfig/README.md) |
| Misconfigurations (exposed secrets, metadata services, etc.) | [Lesson 04 section 1](04-attack-vectors-in-gcp.md#1-misconfigurations-exposed-secrets-metadata-services-etc) | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) (GCP `Metadata-Flavor: Google`) |
| Attacking Google Cloud Storage GCS, Cloud CDN | [Lesson 04 section 2](04-attack-vectors-in-gcp.md#2-attacking-google-cloud-storage-gcs-cloud-cdn) | [bucket-misconfig](labs/bucket-misconfig/README.md) (GCS) |
| Attacking Google Cloud Functions | [Lesson 04 section 3](04-attack-vectors-in-gcp.md#3-attacking-google-cloud-functions) | [serverless-supply-chain](labs/serverless-supply-chain/README.md) |
| Attacking Google Kubernetes Engine | [Lesson 04 section 5](04-attack-vectors-in-gcp.md#5-attacking-google-kubernetes-engine); [chapter 4](../ch4-attacking-kubernetes-cluster-supply-chain/README.md); repo [06 kubernetes](../../06-ai-devsecops/kubernetes/README.md) | [gke-misconfig](labs/gke-misconfig/README.md) |
| Best Practices for Securing the Cloud | [Lesson 05](05-best-practices-for-securing-the-cloud.md); repo [CSPM and IaC scanning](../../cybersecurity-track/10-cloud-security/05-cspm-cnapp-iac-scanning.md) | all labs (rerun after fixes) |
| Hands-on exercises | The syllabus lists none for this chapter. Five extra offline labs are added below. | [Lab index](#lab-index) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "Metadata service" as one thing | **IMDSv2** (session token, hop limit) is the AWS defense; Azure requires `Metadata: true` and GCP requires `Metadata-Flavor: Google`. The headers stop simple GET-only SSRF but not an attacker who controls headers. Legacy GCP metadata endpoints (v1beta1, 0.1) did not need the header, so check old VMs and clusters. |
| CloudFront Origin Access Identity | **Origin Access Control (OAC)** is the newer mechanism (OAI is legacy). Verify current AWS guidance. |
| S3 ACL-based public access | Block Public Access, and for new buckets ACLs are disabled by default (Object Ownership "bucket owner enforced"); verify defaults on your account. |
| GKE legacy features | Legacy ABAC, legacy metadata endpoints and client certificate authentication are legacy settings; use RBAC, Workload Identity Federation for GKE, authorized networks and Binary Authorization. kube-hunter is no longer actively developed; use Trivy (`trivy k8s`) or Kubescape. |
| Azure "Web Apps" and "Application Gateway" names | Services and SKUs were renamed and extended over time (App Service, Application Gateway v2 with WAF); verify current names. Basic auth for SCM/FTP can be disabled. Use managed identities and Entra ID (formerly Azure AD). |
| Service account keys and static secrets | Prefer **Workload Identity Federation** (GCP), federated credentials (Azure) and OIDC roles (AWS) for CI; avoid long-lived keys. |
| Threat matrices | The Microsoft Threat Matrix for Azure is a 2020-era artifact; MITRE ATT&CK for Enterprise (cloud platforms) is updated regularly. Use the live versions. |
| Case studies stop at 2019-2021 | Add: **polyfill.io** CDN domain takeover (2024), **abandoned bucket takeover** research (2025, reported), **tj-actions/changed-files** secret theft from CI (2025), **Shai-Hulud** npm worms stealing cloud tokens (2025-2026), **LLMjacking** with stolen cloud keys (2024). |
| Cloud supply chain = third-party services only | It also covers your **pipeline roles, artifact stores, DNS and CDN** in front of everything. |

## Learning order

1. [Lesson 01](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md) (matrix and shared responsibility). About 4 hours.
2. [Lesson 02](02-attack-vectors-in-aws.md) with [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md), [bucket-misconfig](labs/bucket-misconfig/README.md), [serverless-supply-chain](labs/serverless-supply-chain/README.md) and [deployment-services](labs/deployment-services/README.md). About 8 hours.
3. [Lesson 03](03-attack-vectors-in-azure.md), reusing the same labs to see the Azure shapes. About 3 hours.
4. [Lesson 04](04-attack-vectors-in-gcp.md) with [gke-misconfig](labs/gke-misconfig/README.md). About 4 hours.
5. [Lesson 05](05-best-practices-for-securing-the-cloud.md); read the repo [cloud security track](../../cybersecurity-track/10-cloud-security/README.md) in parallel (CloudTrail detector and IAM analyzer labs). About 4 hours.
6. Then [Chapter 6](../ch6-common-defenses-against-supply-chain-attacks/README.md), where the defenses (signing, SBOM, scanning) are practised.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain`.

| Lab | Focus | Tests |
|---|---|---|
| [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) | Simulated IMDS: v1 vs v2, hop limit, Azure and GCP headers, SSRF fix | 14 |
| [bucket-misconfig](labs/bucket-misconfig/README.md) | S3, Blob, GCS, CDN origin, subdomain takeover auditor | 11 |
| [serverless-supply-chain](labs/serverless-supply-chain/README.md) | Env secrets, layers, dependencies, execution roles | 12 |
| [deployment-services](labs/deployment-services/README.md) | Pipeline role over-privilege, artifact tampering simulation | 11 |
| [gke-misconfig](labs/gke-misconfig/README.md) | Legacy metadata, Workload Identity, legacy ABAC | 10 |

Reused repo labs: [CloudTrail detections and IAM analyzer](../../cybersecurity-track/10-cloud-security/README.md), [architecture reviewer](../../09-enterprise-architecture/README.md), [06 kubernetes checker](../../06-ai-devsecops/kubernetes/README.md), [06 cicd](../../06-ai-devsecops/cicd/README.md), [06 terraform policy checks](../../06-ai-devsecops/terraform/README.md).

## Exam tips

- **Always name the path:** initial access → credential access (metadata or secrets) → privilege (over-broad role) → impact. Then give one preventive and one detective control.
- **IMDSv2 in one breath:** PUT for a token, token on every GET, hop limit 1, no forwarded-for. Azure and GCP use a required header; none of them fix the SSRF itself.
- **Public means three things on GCP:** `allUsers`, `allAuthenticatedUsers`, and a public backend behind a CDN.
- **Bucket and DNS lifecycle:** delete DNS first, keep the bucket name, inventory references. Dangling = takeover.
- **CDN origin:** private origin plus OAC; otherwise the CDN can be bypassed.
- **Serverless still has supply chain:** dependencies, layers, role, triggers, and secrets in env vars.
- **Pipelines are production:** least-privilege role per pipeline, build-only writers for artifacts, digest check, approvals.
- **Workload Identity needs two switches** on GKE: cluster setting and node pool metadata mode.
- **Hedge** version-specific claims ("as documented at the time, verify").

## 15 exam-style questions

<details>
<summary>1. What are the three layers of the shared responsibility split, and what do you always own?</summary>

The provider secures the cloud (facilities, hardware, virtualization, managed control plane). You secure what you put in it. The split moves with the service model (IaaS, PaaS, serverless, SaaS). You always own identities and access policy, data classification and exposure, and your code and configuration.
</details>

<details>
<summary>2. Why is a threat matrix useful, and which cloud matrices should you know?</summary>

It gives a shared vocabulary of tactics and techniques and a coverage checklist (can we prevent and detect each cell?). Know MITRE ATT&CK for Enterprise (cloud platforms) and the Microsoft Threat Matrix for Azure (plus its Kubernetes and storage siblings). Use the live versions.
</details>

<details>
<summary>3. Explain an SSRF to the metadata service and why IMDSv2 helps.</summary>

An app that fetches attacker-chosen URLs can be told to request the metadata address and return role credentials. IMDSv2 needs a PUT to get a session token and that token on later GETs, rejects forwarded requests, and uses a small hop limit so containers one hop away cannot get a token. A simple GET-only SSRF fails. The vulnerability and any over-privileged role still need fixing.
</details>

<details>
<summary>4. Azure and GCP require headers for metadata. Do they stop SSRF?</summary>

They stop simple GET-only SSRF that cannot add headers (`Metadata: true`, `Metadata-Flavor: Google`). If the attacker controls headers or the whole request, they do not. Add outbound URL allow-listing, egress filtering and least-privilege identities.
</details>

<details>
<summary>5. List four S3 attack patterns and a control for each.</summary>

Public read (Block Public Access), public write (never allow, versioning), bucket takeover of a deleted name (inventory references, keep the bucket), unsigned artifact download (hash/signature check). Also subdomain takeover (remove DNS first) and website hosting without HTTPS (CDN in front).
</details>

<details>
<summary>6. How can a CDN be bypassed, and how do you prevent it?</summary>

If the origin bucket is publicly readable, requests go straight to it and skip WAF, signed URL and geo rules. Make the origin private and permit only the distribution (Origin Access Control on CloudFront; signed requests and restricted origins on other CDNs).
</details>

<details>
<summary>7. What is a subdomain takeover and why is it a supply-chain risk?</summary>

A DNS record (often a CNAME) points to a cloud resource that was deleted. An attacker creates that resource name and serves content on your domain, which can host scripts or updates your users trust. Remove DNS before deleting resources, and scan for dangling records.
</details>

<details>
<summary>8. Name five serverless supply-chain risks.</summary>

Vulnerable or malicious dependencies, untrusted or unpinned layers, secrets in environment variables, over-permissive execution roles, unauthenticated triggers, event injection, and code replacement by someone with update rights.
</details>

<details>
<summary>9. Why is `lambda:UpdateFunctionCode` or `iam:PassRole` on `*` dangerous?</summary>

The first lets a principal replace function code (persistence and code execution under the function's role). The second lets a principal attach powerful roles to resources it controls (privilege escalation). Restrict both and alert on use.
</details>

<details>
<summary>10. Describe an artifact-bucket tampering attack on a deployment pipeline and two defenses.</summary>

An attacker with write access to the artifact store swaps the build output between build and deploy; the deploy role (often over-privileged) ships it. Defenses: only the build identity can write, and the deploy stage verifies a digest or signature recorded at build time. Also least-privilege roles and approvals.
</details>

<details>
<summary>11. Which Azure Blob settings do you review first?</summary>

Account-level "allow blob public access", container access levels, HTTPS-only, shared key access, SAS lifetime and permissions (prefer user delegation SAS), and dangling DNS to storage endpoints.
</details>

<details>
<summary>12. What is the difference between `allUsers` and `allAuthenticatedUsers` on GCP?</summary>

`allUsers` is anyone on the internet. `allAuthenticatedUsers` is anyone signed in with any Google account, which is almost everyone. Treat both as public.
</details>

<details>
<summary>13. Why does a compromised pod on an old GKE cluster become project-level access?</summary>

Without Workload Identity the pod can read the node service account token from the metadata server. If that account is the default Compute SA with a broad role, the attacker inherits it. Fix with Workload Identity (and the GKE metadata server mode on node pools), a minimal node SA, RBAC only, and private cluster settings.
</details>

<details>
<summary>14. What is legacy ABAC on GKE?</summary>

An older authorization mode that gives broad rights through static policy; it should be disabled in favour of RBAC.
</details>

<details>
<summary>15. If you had a week to improve cloud supply-chain security, what are the first three things?</summary>

1) Close public exposure and remove secrets from code and environment variables (Block Public Access, secret scanning, rotate). 2) Cut identity risk: no long-lived keys, least-privilege roles for pipelines and functions, harden metadata access. 3) Protect delivery integrity and detection: writers-only-build artifact stores, digest or signature checks, and audit-log alerts for key, policy and function-code changes.
</details>

## References

- MITRE ATT&CK (cloud platforms); Microsoft Threat Matrix for Azure; provider shared responsibility documents.
- AWS (IMDSv2, S3 Block Public Access, CloudFront OAC, Lambda), Azure (managed identities, Storage, Functions, App Service), GCP (metadata server, Cloud Storage, GKE hardening, Binary Authorization) documentation. Verify current pages.
- CIS Benchmarks for AWS, Azure, GCP and Kubernetes.
- Repo: [cybersecurity track 10 cloud security](../../cybersecurity-track/10-cloud-security/README.md), [09 enterprise architecture](../../09-enterprise-architecture/README.md), [06 AI DevSecOps](../../06-ai-devsecops/README.md).
