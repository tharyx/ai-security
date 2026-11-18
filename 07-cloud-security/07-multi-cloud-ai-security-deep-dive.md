# Module 07 — Multi-Cloud AI Security Architecture

**Effort:** 18–24 hours. **Outcome:** Translate security outcomes across AWS, Azure and Google Cloud without assuming products are identical.

## 1. Design by outcome
Define security outcomes first, then map provider-specific services. Verify exact feature scope, region, service tier and shared-responsibility boundary.

| Capability | AWS examples | Azure examples | Google Cloud examples |
|---|---|---|---|
| Managed AI | Amazon Bedrock | Azure AI Foundry / Azure OpenAI offerings | Vertex AI |
| Identity | IAM, IAM Identity Center | Entra ID, managed identities | Cloud IAM, service accounts |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| Keys | KMS | Key Vault / Managed HSM | Cloud KMS / HSM |
| Private network | VPC, private connectivity | VNet, Private Link | VPC, Private Service Connect |
| Audit | CloudTrail | Activity Log, diagnostics | Cloud Audit Logs |
| Threat detection | GuardDuty, Security Hub | Defender for Cloud | Security Command Center |
| Kubernetes | EKS | AKS | GKE |
| Policy | Organizations/SCP/Config | Azure Policy | Organization Policy |

## 2. Identity architecture
Separate human, CI/CD, application runtime, model endpoint, ingestion, retrieval, MCP server and agent executor identities. Use workload identity and short-lived credentials. Avoid a shared administrator service principal.

## 3. Network architecture
Isolate dev/test/prod; use private endpoints where appropriate; define egress allowlists; block metadata endpoints from untrusted tools; separate model-serving, data and management planes; log egress where justified; do not expose MCP servers publicly without reviewed design.

## 4. Key and secret lifecycle
Centralize secrets, retrieve through workload identity, rotate/revoke, keep credentials out of prompts/source/logs, define key ownership and separation of duties, document backup and recovery.

## 5. Lab — same RAG design in three clouds
For AWS, Azure and GCP document identity principal/trust, model endpoint access, vector-store encryption, private network path, secret retrieval, audit destination, alerting, deployment identity, data region/retention and cost guardrails.

## 6. Architecture decision record
For each provider choice document context, constraints, options, decision, security consequences, operational cost, portability impact, residual risk and review date.

## Anti-patterns
- Assuming similar product names mean equivalent controls.
- Duplicating secrets without lifecycle ownership.
- Sending data across regions/providers without data-flow review.
- Static CI keys when federation is available.
- Treating provider certification as proof your application is compliant.
- Hiding provider-specific security behavior behind an abstraction that removes necessary controls.

## Acceptance criteria
Equivalent outcomes mapped to three providers; differences recorded; CI avoids long-lived keys where possible; data flows/residency documented; model, vector store and tool access appropriately restricted.
