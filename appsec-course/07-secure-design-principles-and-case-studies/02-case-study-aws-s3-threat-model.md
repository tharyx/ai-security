# Lesson 02: Case Study: AWS S3 Threat Model

**Syllabus item covered:** [CTMP 5] "Case Study of AWS S3 Threat Model".

**Time:** 1 hour plus lab. **Safety:** fictional buckets and accounts; the lab reads JSON fixtures only.

> **DBA analogy.** An S3 bucket policy is a GRANT statement attached to the table instead of to the user. `Principal: "*"` is `GRANT SELECT ON orders TO PUBLIC`.

## 1. Why S3 is a classic threat modeling case

S3 looks simple (put and get objects) but has many control layers: IAM policies, bucket policies, ACLs, Block Public Access at account and bucket level, access points, encryption options, versioning and Object Lock, VPC endpoints and endpoint policies, logging. Most S3 data leaks came from **configuration**, not from AWS bugs. That makes it a good teaching case for threat modeling a managed cloud service under the **shared responsibility model**: AWS secures the service; you secure your configuration and data.

Sources to study (verify access and currency): **TrustOnCloud** publishes a detailed "ThreatModel for Amazon S3" (control catalogue mapped to threats; check its access terms), and AWS documents **Security best practices for Amazon S3**. Recent AWS defaults help: Block Public Access and ACLs disabled (BucketOwnerEnforced) for new buckets since April 2023, and default SSE-S3 encryption since January 2023 (verify).

## 2. DFD

```text
[Users / apps] --HTTPS--> (S3 API endpoint) --> [Bucket: objects, versions]
[Other AWS services (CloudTrail, log delivery)] --service principal--> [Bucket]
[Partner account] --cross-account role--> [Bucket]
[VPC workloads] --VPC endpoint--> [Bucket]
Trust boundaries: Internet | your AWS account | other AWS accounts | AWS service principals
```

## 3. Threat table (ids match the lab)

| Id | STRIDE | Threat | Mitigation (verify control names) |
|---|---|---|---|
| S3-T1 | Information Disclosure | Bucket or objects made public by policy or ACL | S3 Block Public Access (all four settings) at account and bucket level |
| S3-T2 | Information Disclosure | Policy grants `Principal: "*"` without conditions | No unconditional public Allow; use conditions (`aws:PrincipalOrgID`, VPC endpoint) or CloudFront with OAC |
| S3-T3 | Information Disclosure / Tampering | Requests over plain HTTP | Deny when `aws:SecureTransport` is false; enforce TLS 1.2+ (`s3:TlsVersion` condition) |
| S3-T4 | Elevation of Privilege | Object ACLs let uploaders keep ownership or grant access | Object Ownership = BucketOwnerEnforced (ACLs disabled) |
| S3-T5 | Information Disclosure | Data readable if storage or keys are compromised; no key control | SSE-KMS with a customer managed key for sensitive data; key policy separation |
| S3-T6 | Tampering / Denial of Service | Ransomware or accidental deletion/overwrite | Versioning, Object Lock (compliance/governance mode), MFA Delete, replication, backups |
| S3-T7 | Repudiation | No record of who read or deleted objects | CloudTrail data events, server access logs, alerts |
| S3-T8 | Elevation of Privilege | Confused deputy: a service principal writes on behalf of another account | `aws:SourceAccount` / `aws:SourceArn` conditions on service principals |
| S3-T9 | Elevation of Privilege | Over-broad `s3:*` grants to roles or partners | Least-privilege actions and resource prefixes; IAM Access Analyzer |
| S3-T10 | Information Disclosure | Data exfiltrated from your VPC to an attacker's bucket | VPC endpoint policies restricting buckets; `aws:ResourceOrgID` conditions |
| S3-T11 | Spoofing | Bucket name squatting / takeover of a deleted bucket name referenced by apps | Do not reference deleted buckets; owner checks (`ExpectedBucketOwner`); account-regional naming |

## 4. Principles in this case

- **Fail-safe defaults:** Block Public Access and ACLs-disabled defaults for new buckets.
- **Least privilege:** scoped actions, prefixes, access points per application.
- **Complete mediation:** every request evaluated against IAM, bucket policy, BPA, endpoint and SCPs.
- **Separation of privilege:** KMS key policy separate from bucket policy (two permissions needed to read encrypted data).

## 5. Scenario

A marketing team needed to share a product feed with a partner and set `Principal: "*"` on `exports/`. Three months later the same bucket held customer CSV exports under `exports/customers/`. A search engine for open buckets found them. A threat model would have caught three things at design time: S3-T1/T2 (public access), mixing data classifications in one bucket (least common mechanism), and no data events logging (S3-T7) to know what was downloaded.

## 6. Lab

The [cloud-native-threat-model-checks lab](labs/cloud-native-threat-model-checks/README.md) checks bucket configuration and policy JSON against S3-T1 to S3-T9.

## References

- AWS: Security best practices for Amazon S3; Blocking public access; Controlling object ownership; IAM Access Analyzer (verify current pages).
- TrustOnCloud, "ThreatModel for Amazon S3" (verify availability).
- Repo: [AWS AI security](../../09-enterprise-architecture/02-aws-ai-security.md), [cybersecurity-track cloud security](../../cybersecurity-track/10-cloud-security/README.md).
