# Multi-Cloud AI Security Control Matrix

This is a control-outcome map, not a claim that provider products are identical. Verify service availability, feature scope, region, pricing and shared-responsibility boundaries for the selected deployment.

| Control outcome | AWS examples | Azure examples | Google Cloud examples |
|---|---|---|---|
| Managed model access | Amazon Bedrock | Azure AI Foundry / Azure OpenAI offerings | Vertex AI |
| Identity | IAM, IAM Identity Center, workload roles | Microsoft Entra ID, managed identities | Cloud IAM, service accounts |
| Secrets | Secrets Manager, Systems Manager Parameter Store | Key Vault | Secret Manager |
| Encryption keys | KMS | Key Vault / Managed HSM | Cloud KMS / Cloud HSM |
| Network isolation | VPC, private connectivity, security groups | VNet, Private Link, NSG | VPC, Private Service Connect, firewall |
| Audit | CloudTrail, service logs | Azure Activity Log, diagnostic settings | Cloud Audit Logs |
| Threat detection | GuardDuty, Security Hub | Defender for Cloud | Security Command Center |
| Container platform | EKS, ECS | AKS, Container Apps | GKE, Cloud Run |
| Policy/config | Organizations, SCPs, Config | Azure Policy, management groups | Organization Policy, Security Command Center |
| CI/CD federation | IAM OIDC roles | Workload identity federation / service connections | Workload Identity Federation |

## Architecture requirements independent of cloud
1. Central identity and short-lived credentials.
2. Private network paths where feasible; controlled egress.
3. Encryption in transit and at rest; managed key lifecycle.
4. Separate environments and accounts/subscriptions/projects.
5. Data classification and residency requirements.
6. Centralized audit logs with retention and access controls.
7. Model and dataset inventory/provenance.
8. Per-tenant authorization and isolation.
9. Quotas, budgets and abuse monitoring.
10. Backup, recovery, incident response and exit strategy.

## Lab
Design the same secure RAG architecture on AWS, Azure and GCP. For each, document:
- identity principal and trust policy;
- network boundary and private connectivity;
- encryption/key ownership;
- secrets retrieval;
- logging and alerting;
- deployment identity;
- data location and retention;
- provider-managed versus customer-managed controls;
- cost and operational trade-offs.

## Multi-cloud anti-patterns
- Assuming a service name implies equivalent security behavior.
- Duplicating identities and secrets without lifecycle ownership.
- Sending data across regions/providers without data-flow review.
- Using long-lived static keys in CI/CD.
- Treating provider compliance certifications as proof that your application is compliant.
- Building portability abstractions that erase important provider-specific controls.
