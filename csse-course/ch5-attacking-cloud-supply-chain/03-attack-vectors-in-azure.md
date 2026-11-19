# Lesson 03: Attack Vectors in Azure

> **Chapter:** 5 · Attacking the Cloud Supply Chain · **Time:** ~4 hours
> **You will:** explain how Azure misconfigurations, the Instance Metadata Service, Blob storage and Application Gateway, Azure Functions and Web Apps (App Service) are attacked, and choose the control for each.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md), [Lesson 02](02-attack-vectors-in-aws.md); [Azure in 09](../../09-enterprise-architecture/03-azure-ai-security.md) |
| **Labs** | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) (Azure IMDS) · [bucket-misconfig](labs/bucket-misconfig/README.md) (Blob, SAS) · [serverless-supply-chain](labs/serverless-supply-chain/README.md) (Functions) · [deployment-services](labs/deployment-services/README.md) (Azure DevOps) |
| **Syllabus lines** | Attack Vectors in Azure · Misconfigurations (exposed secrets, metadata services, etc.) · Attacking Azure Blob storage, Azure Application Gateway · Attacking Azure Functions · Attacking Web Apps |

> **Hedging.** Azure names and defaults change. Everything is written to the best of our knowledge: **verify in Microsoft documentation**. Test only your own subscriptions.

## 1. Misconfigurations (exposed secrets, metadata services, etc.)

### 1.1 Exposed secrets

- **Storage account keys and connection strings** in app settings, repos or pipeline variables. A shared key gives full account access and cannot be scoped.
- **SAS tokens** with long expiry, broad permissions (`rwdl`) or no IP restriction, pasted into links and scripts.
- **Service principal secrets** in repositories and CI variables.
- **Key Vault** with an access policy or role that grants "get secrets" too widely.
- **App settings** showing secrets in plain text to every contributor.

Controls: **managed identities** instead of secrets; Entra ID authorization on storage (disable shared key where possible); short-lived SAS (user delegation SAS signed with Entra credentials); Key Vault references; secret scanning on push.

### 1.2 The Azure Instance Metadata Service (IMDS)

On Azure VMs, the IMDS sits at `169.254.169.254`. It returns instance data and, for managed identities, **access tokens** for Azure resources. A request must carry the header `Metadata: true`, and requests that include a forwarded-for header are rejected. The header stops a **simple GET-only SSRF** that cannot add headers. It does **not** help if the attacker can control request headers (full request control or a header-injection bug).

| Concern | Control |
|---|---|
| SSRF in a VM or App Service app steals a managed identity token | validate and restrict outbound URLs; block link-local from app code; least-privilege identity |
| Token scope too broad | assign the narrowest role at the narrowest scope; one identity per workload |
| Other platforms use different endpoints | App Service and Functions use an identity endpoint exposed by environment variables rather than the VM IMDS (verify the details for your service) |

**Lab:** [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) includes an Azure IMDS simulator: missing header returns an error; a bug that lets the attacker set the header gets the token.

## 2. Attacking Azure Blob storage, Azure Application Gateway

### 2.1 Blob storage

| Attack | Detail | Control |
|---|---|---|
| **Anonymous container access** | container set to allow public read; anyone lists or downloads blobs | disable "allow blob public access" at the account level |
| **Account key abuse** | leaked key gives full control; no per-user audit | disable shared key access; use Entra ID |
| **Long-lived SAS** | link works for years | short expiry, stored access policies, user delegation SAS |
| **HTTP allowed** | secure transfer not required | require HTTPS |
| **Static website and CDN** | `*.web.core...` endpoints; a CNAME that points to a deleted storage account is a **subdomain takeover** | remove DNS when deleting resources; monitor dangling CNAMEs |
| **Tampering with deployed assets** | writable container holds scripts or packages other systems download | restrict write; immutability and versioning; verify hashes |

### 2.2 Application Gateway (with WAF)

Application Gateway is a layer-7 load balancer and optional web application firewall.

- **WAF in detection-only mode** or missing: attacks are logged, not blocked.
- **Backend reachable directly**, bypassing the gateway: lock backends to the gateway with network rules.
- **Weak TLS settings**, default certificates, expired certificates.
- **Misrouted or over-trusted headers** (for example trusting `X-Forwarded-*` headers without validation) can lead to SSRF or access-control bypass in the backend.
- **Dangling DNS**: a public name that points at a removed gateway frontend IP.

Controls: WAF in prevention mode with current managed rule sets, private backends, TLS policy, diagnostic logs to your SIEM.

**Lab:** [bucket-misconfig](labs/bucket-misconfig/README.md) has Blob and SAS fixtures plus DNS takeover checks.

## 3. Attacking Azure Functions

| Vector | Detail | Control |
|---|---|---|
| **Function keys and anonymous triggers** | `anonymous` authorization level; leaked function or host keys | require authorization, prefer Entra ID authentication, rotate keys |
| **Dependencies** | npm or Python packages in the deployment package | SCA, lockfiles, hash pinning |
| **App settings secrets** | `AzureWebJobsStorage` connection strings and others with full account keys | managed identity based connections, Key Vault references |
| **Deployment channels** | Kudu / SCM site, FTP, zip deploy credentials (publish profiles) | disable basic auth for SCM and FTP, use CI with federated identity |
| **Managed identity too powerful** | a function with Contributor on the subscription | least privilege |
| **Injection through triggers** | queue messages, blob names, HTTP bodies | validate input |

**Lab:** [serverless-supply-chain](labs/serverless-supply-chain/README.md) (an Azure Functions fixture with a connection string in settings).

## 4. Attacking Web Apps

Azure App Service web apps share many risks with any web app, plus platform-specific ones:

- **Application vulnerabilities** (injection, SSRF, deserialization) lead to managed identity token theft (section 1.2).
- **Publish profile and SCM credentials** leaked, giving the ability to push code. Treat them like production passwords and disable basic authentication.
- **Public access by default**: restrict with access restrictions, private endpoints, and authentication (built-in Entra authentication).
- **Deployment slots and settings** that copy secrets between environments.
- **Supply chain through the build**: GitHub Actions or Azure DevOps pipelines with a service connection that can deploy anywhere, a pipeline editable by many, and artifact feeds that accept packages from anyone (dependency confusion, see [chapter 2](../ch2-attacking-code-and-application-supply-chain/README.md)).
- **Container-based apps** pull images from a registry; use private registries, digests and signature checks.

**Controls.** Managed identity with narrow roles, private endpoints, WAF, disabled basic auth, pipeline federation (no stored secrets), protected branches and required approvals on the deployment environment ([chapter 6 change control](../ch6-common-defenses-against-supply-chain-attacks/03-change-control-and-licensed-code.md)).

**Lab:** [deployment-services](labs/deployment-services/README.md): an Azure DevOps service connection with Owner rights, authorized for all pipelines.

## Defend (summary)

Managed identities and no shared keys · short-lived user delegation SAS · account-level block of public blob access · WAF in prevention mode · private backends · disable SCM/FTP basic auth · least-privilege roles at narrow scopes · Defender for Cloud and Azure Policy as guardrails · [Microsoft Threat Matrix for Azure](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md#22-cloud-threat-matrices) as your checklist.

## Hands-on

1. Run [bucket-misconfig](labs/bucket-misconfig/README.md) and list every Azure finding with its fix.
2. In [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md), explain why `attacker_controls_headers=True` succeeds against the header defense.
3. Map two Azure findings onto the Microsoft matrix columns.

## Scenarios

- **A partner SAS valid for two years** is posted in a ticket. Impact? (Anyone with the link keeps access, including write if granted.)
- **A CNAME `files.corp.example` points to a removed storage account.** What is the risk? (Takeover and content served on your domain.)

## Interview Q&A

<details><summary>Why does the `Metadata: true` header not fully protect Azure IMDS?</summary>

It blocks simple SSRF where the attacker cannot add headers. If the vulnerability lets the attacker control headers or the whole request, the header is just another field to set. You still need egress controls and least-privilege identities.
</details>

<details><summary>Why prefer user delegation SAS to account-key SAS?</summary>

It is signed with Entra ID credentials, inherits their permissions, is limited in lifetime, and can be audited. A key-signed SAS cannot be revoked without rotating the account key.
</details>

<details><summary>What is the supply-chain risk in a deployment slot swap or a publish profile?</summary>

A leaked publish profile lets an attacker push code straight to production, bypassing your pipeline reviews.
</details>

## References

- Microsoft Learn: managed identities, Instance Metadata Service, Storage security recommendations, Application Gateway WAF, Azure Functions security (verify current pages).
- Microsoft Threat Matrix for Azure (security blog; verify the latest).
- Repo: [Azure in 09](../../09-enterprise-architecture/03-azure-ai-security.md), [cloud identity](../../cybersecurity-track/10-cloud-security/02-cloud-identity.md).
