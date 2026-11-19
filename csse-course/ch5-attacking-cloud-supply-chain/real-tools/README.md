# Real-tool notes for chapter 5 (hedged, optional)

The chapter 5 labs run offline. This page lists real commands and tools you may use **on your own cloud accounts** to check the same things. Names, flags and defaults change: **verify in the provider documentation**. Never test accounts or resources you do not own, and never paste keys or tokens into chat or repositories.

| Check | AWS | Azure | GCP | Lab |
|---|---|---|---|---|
| Metadata hardening | `aws ec2 modify-instance-metadata-options --http-tokens required --http-put-response-hop-limit 1` | review managed identity roles (`az role assignment list`) | review service account roles and node pool metadata mode | [cloud-metadata-ssrf](../labs/cloud-metadata-ssrf/README.md) |
| Public storage | `aws s3api get-public-access-block`, `get-bucket-policy-status` | `az storage account show` (public blob access, shared key, HTTPS) | `gcloud storage buckets get-iam-policy`, public access prevention | [bucket-misconfig](../labs/bucket-misconfig/README.md) |
| Dangling DNS | list Route 53 records, check each CNAME target exists | check CNAMEs to `*.blob.*`, app and gateway hostnames | check CNAMEs to storage and load balancers | [bucket-misconfig](../labs/bucket-misconfig/README.md) |
| Function config | `aws lambda get-function-configuration` | `az functionapp config appsettings list` | `gcloud functions describe` | [serverless-supply-chain](../labs/serverless-supply-chain/README.md) |
| Pipeline roles | `aws codepipeline get-pipeline`, `aws iam list-attached-role-policies` | Azure DevOps service connection security | `gcloud projects get-iam-policy` (Cloud Build SA) | [deployment-services](../labs/deployment-services/README.md) |
| Kubernetes | `aws eks describe-cluster` (AWS: see chapter 4) | `az aks show` | `gcloud container clusters describe`, `trivy k8s`, Kubescape | [gke-misconfig](../labs/gke-misconfig/README.md) |

## Posture tools (check maintenance and that they are read-only)

- **Prowler** and **ScoutSuite** (multi-cloud posture scanners), **Steampipe** (query cloud APIs with SQL), cloud-provider posture services (CSPM), **Trivy** and **Checkov** for IaC. See [CSPM, CNAPP and IaC scanning](../../../cybersecurity-track/10-cloud-security/05-cspm-cnapp-iac-scanning.md).
- Use read-only roles (for example the provider's "security audit" or "reader" roles) for scanners.

## Attack-technique references (read, do not run against others)

- MITRE ATT&CK Cloud matrix and Microsoft Threat Matrix for Azure: see [lesson 01](../01-cloud-ecosystem-attack-surface-and-shared-responsibility.md#22-cloud-threat-matrices).
- Pacu, CloudGoat, flAWS-style training environments exist for practice **in your own sandbox accounts**; verify they are maintained and deploy them only in disposable accounts with billing alerts.
