# Lesson 05: Best Practices for Securing the Cloud

> **Chapter:** 5 · Attacking the Cloud Supply Chain · **Time:** ~4 hours
> **You will:** build a cross-cloud checklist from the attacks in lessons 02 to 04, connect it to guardrails, scanning and logging, and prioritize it.

| | |
|---|---|
| **Prerequisites** | Lessons [01](01-cloud-ecosystem-attack-surface-and-shared-responsibility.md) to [04](04-attack-vectors-in-gcp.md) |
| **Related repo lessons** | [CSPM, CNAPP and IaC scanning](../../cybersecurity-track/10-cloud-security/05-cspm-cnapp-iac-scanning.md) · [network and data protection](../../cybersecurity-track/10-cloud-security/04-network-and-data-protection.md) · [cloud incident response](../../cybersecurity-track/10-cloud-security/06-cloud-incident-response.md) · [multi-cloud matrix](../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md) · [06 terraform](../../06-ai-devsecops/terraform/README.md) |
| **Labs** | all five chapter 5 labs; rerun them after applying the fixes |
| **Syllabus line** | Best Practices for Securing the Cloud |

## 1. The checklist, grouped by attack

| Attack from this chapter | Control (any cloud) | Lab that shows it |
|---|---|---|
| Metadata SSRF | require session tokens / headers; allow-list outbound URLs; block link-local from app code; low-privilege identity | [cloud-metadata-ssrf](labs/cloud-metadata-ssrf/README.md) |
| Public or writable storage | account-level public access block; no anonymous write; versioning; encryption | [bucket-misconfig](labs/bucket-misconfig/README.md) |
| CDN origin bypass | private origin with origin access control; WAF at the edge | [bucket-misconfig](labs/bucket-misconfig/README.md) |
| Dangling DNS / bucket takeover | delete DNS before resources; inventory references; scan for dangling records | [bucket-misconfig](labs/bucket-misconfig/README.md) |
| Dependency and layer risk in functions | lockfile + SCA + hash pins; trusted layers only; pinned versions | [serverless-supply-chain](labs/serverless-supply-chain/README.md) |
| Secrets in env vars | secrets manager references; scanners | [serverless-supply-chain](labs/serverless-supply-chain/README.md), [trufflehog](../ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md) |
| Over-permissive roles | one role per workload and pipeline; no wildcards; permission boundaries; access analyzer | [serverless-supply-chain](labs/serverless-supply-chain/README.md), [deployment-services](labs/deployment-services/README.md) |
| Pipeline and artifact tampering | writers limited to the build identity; digest check; signing; approvals | [deployment-services](labs/deployment-services/README.md) |
| Kubernetes node identity | workload identity; private cluster; RBAC; network policy | [gke-misconfig](labs/gke-misconfig/README.md) |

## 2. Foundation controls

1. **Organization and account structure.** Separate accounts, subscriptions or projects for prod, dev and build. A compromised build account must not be prod.
2. **Identity first.** Single sign-on, MFA, federation for CI, no long-lived keys, regular access reviews, break-glass accounts with alerting. See [cloud identity](../../cybersecurity-track/10-cloud-security/02-cloud-identity.md).
3. **Guardrails as code.** Service control policies, Azure Policy, organization policies; Terraform or other IaC with policy checks in CI ([06 terraform](../../06-ai-devsecops/terraform/README.md)).
4. **Posture management.** CSPM or CNAPP findings, IaC scanning, drift detection ([05 CSPM lesson](../../cybersecurity-track/10-cloud-security/05-cspm-cnapp-iac-scanning.md)).
5. **Logging and detection.** Control-plane audit logs (CloudTrail, Azure Activity Log, Cloud Audit Logs) in a separate, protected account; alerts for key creation, policy changes, logging disabled, function code updates, public exposure changes ([CloudTrail lab](../../cybersecurity-track/10-cloud-security/README.md)).
6. **Network.** Private endpoints, egress filtering, WAF, segmentation ([network and data protection](../../cybersecurity-track/10-cloud-security/04-network-and-data-protection.md)).
7. **Data.** Classify; encrypt with customer-managed keys where policy requires it; backup with immutability; versioning.
8. **Supply-chain controls on the delivery path.** Signed artifacts, verified at deploy; SBOMs stored; provenance. This is the content of [chapter 6](../ch6-common-defenses-against-supply-chain-attacks/README.md).
9. **Incident readiness.** Playbooks for leaked keys, public bucket, compromised pipeline role ([cloud incident response](../../cybersecurity-track/10-cloud-security/06-cloud-incident-response.md)).

## 3. Benchmarks and frameworks to name

- **CIS Benchmarks** for AWS, Azure and GCP (and Kubernetes). Verify versions.
- **Provider well-architected / security best-practice guides.**
- **CSA Cloud Controls Matrix** (CCM) and the repo's [multi-cloud control matrix](../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md).
- **NIST** guidance such as SP 800-53 controls and cloud-related publications.

## 4. Prioritizing

Start where an attacker gets the most for the least work: (1) public exposure and secrets, (2) over-privileged identities, (3) pipeline and artifact integrity, (4) detection, (5) hardening depth. A risk-based order is in the [vulnerability management track](../../cybersecurity-track/08-vulnerability-management/README.md).

## Hands-on

1. Take the five lab demos and produce one combined findings table with owner and fix for each critical.
2. Write a one-page "cloud supply-chain baseline" for your team with ten controls from section 2.
3. Choose three of your findings and write the detection that would have caught the attacker's next step.

## Scenarios

- **You have one week.** Which three controls do you apply first, and why? (Public access block and secrets cleanup; IMDSv2/metadata hardening and least-privilege roles for pipelines; audit logging with the five key alerts.)

## Interview Q&A

<details><summary>Give five cloud best practices that also reduce supply-chain risk.</summary>

No long-lived credentials (federation), least-privilege pipeline roles, private writable-only-by-build artifact stores, signed and verified artifacts, and audit logging with alerts on changes to functions, roles and keys.
</details>

<details><summary>Why keep audit logs in a separate account?</summary>

An attacker who gains admin in the workload account cannot delete or edit the evidence.
</details>

<details><summary>Where does policy-as-code fit?</summary>

In the pipeline before apply (plan scanning) and in the cloud itself as guardrails, so misconfigurations are blocked rather than reported later.
</details>

## References

- CIS Benchmarks; CSA Cloud Controls Matrix; provider security best-practice guides (verify current versions).
- Repo: [cybersecurity track 10 cloud security](../../cybersecurity-track/10-cloud-security/README.md), [09 enterprise architecture](../../09-enterprise-architecture/README.md).
