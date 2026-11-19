# Lab: Cloud Metadata SSRF: IMDSv1 vs IMDSv2, Azure and GCP headers

**Lessons:** [02 section 1.2](../../02-attack-vectors-in-aws.md#12-the-instance-metadata-service-imds) · [03 section 1.2](../../03-attack-vectors-in-azure.md#12-the-azure-instance-metadata-service-imds) · [04 section 1.2](../../04-attack-vectors-in-gcp.md#12-the-metadata-server). Chapter guide: [README](../../README.md). Related repo labs: [cloud security track](../../../../cybersecurity-track/10-cloud-security/README.md) (CloudTrail detections, IAM analyzer), [09 enterprise architecture](../../../../09-enterprise-architecture/README.md) (cloud controls).

**Course status:** the chapter 5 syllabus lists no hands-on exercises; this lab is an **extra offline practice**. **Time:** 60 minutes. **Tests:** 14, all offline.

**Safety:** no cloud account, no network, no real credentials. Everything is a fixture or an in-process simulation; keys are FAKE; domains are `.example`. Real-tool commands below are for **your own** accounts only and are hedged: verify them in the provider docs.

## What the offline twin does

`imds.py` has **in-process** metadata services (no sockets): an AWS-style IMDS with an optional **IMDSv1** and a **required-token IMDSv2** (PUT to get a token, token header on GETs, `X-Forwarded-For` rejection, a **hop limit**), an Azure-style IMDS that needs `Metadata: true`, and a GCP-style server that needs `Metadata-Flavor: Google`. A `vulnerable_preview` function is the classic SSRF (fetch any URL). `is_blocked` and `safe_preview` are the app-side fix: decimal and hex IP forms, IPv4-mapped IPv6, names that resolve to internal addresses, and redirect re-checks.

## Steps

```text
.venv/Scripts/python csse-course/ch5-attacking-cloud-supply-chain/labs/cloud-metadata-ssrf/demo.py
.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain/labs/cloud-metadata-ssrf -v
```

1. Run the demo: IMDSv1 leaks FAKE credentials, IMDSv2 returns 401 to a simple GET.
2. Read `test_header_defense_...`: when the attacker controls headers the Azure and GCP header checks fall, but IMDSv2 still needs a token from a PUT.
3. Raise `hop_limit` to 2 and see the container-side token request succeed. When is that acceptable? (Almost never: prefer pod-level identity.)
4. Add a new obfuscated host form (for example an octal IP) to `is_blocked` tests.

## Expected output (real run)

```text
IMDSv1 (optional)  simple GET SSRF -> 200 {"Code": "Success", "AccessKeyId": "ASIAFAKEFAKE
IMDSv2 (required)  simple GET SSRF -> 401 unauthorized: token required (IMDSv2)
IMDSv2 token request from a container (2 hops) -> 0 (dropped)
Azure GET without Metadata header -> 400
Azure with attacker-set header    -> 200
GCP no Metadata-Flavor            -> 403
safe_preview, decimal-IP form     -> 403
```

## Real-tool guide (hedged)

```text
# AWS (verify in the EC2 docs): require IMDSv2 on an instance you own
aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 1
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens]'
# Azure and GCP: check the managed identity and service account attached to the workload, and its roles
az vm identity show -g <rg> -n <vm>
gcloud compute instances describe <vm> --format='value(serviceAccounts[].email)'
```
Only run these against **your own** account. Never send requests to the metadata address of a system you do not own. Organization policy can require IMDSv2 for new instances (verify the current option names).
