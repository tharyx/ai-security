# Lab: Storage and CDN Misconfigurations: S3, Blob, GCS, CDN origins and subdomain takeover

**Lessons:** [02 section 2](../../02-attack-vectors-in-aws.md#2-attacking-managed-services-like-s3-cloudfront-cdn) · [03 section 2](../../03-attack-vectors-in-azure.md#2-attacking-azure-blob-storage-azure-application-gateway) · [04 section 2](../../04-attack-vectors-in-gcp.md#2-attacking-google-cloud-storage-gcs-cloud-cdn). Chapter guide: [README](../../README.md). Related repo labs: [cloud security track](../../../../cybersecurity-track/10-cloud-security/README.md) (CloudTrail detections, IAM analyzer), [09 enterprise architecture](../../../../09-enterprise-architecture/README.md) (cloud controls).

**Course status:** the chapter 5 syllabus lists no hands-on exercises; this lab is an **extra offline practice**. **Time:** 60 minutes. **Tests:** 11, all offline.

**Safety:** no cloud account, no network, no real credentials. Everything is a fixture or an in-process simulation; keys are FAKE; domains are `.example`. Real-tool commands below are for **your own** accounts only and are hedged: verify them in the provider docs.

## What the offline twin does

`audit.py` reads `fixtures/estate.json` (S3 policies and ACLs, Azure storage accounts with containers and SAS, GCS IAM, CDN distributions, DNS CNAMEs) and reports: public read and **public write**, legacy AllUsers ACLs, website hosting over HTTP, Block Public Access off, Azure public containers, long-lived SAS, shared keys, GCS `allUsers` and `allAuthenticatedUsers` (read or write), **CDN origin without OAC**, website origins, **CDN origin that no longer exists** (bucket takeover), and **dangling DNS CNAMEs** (subdomain takeover).

## Steps

```text
.venv/Scripts/python csse-course/ch5-attacking-cloud-supply-chain/labs/bucket-misconfig/demo.py
.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain/labs/bucket-misconfig -v
```

1. Run the demo and sort the findings by who must fix them (storage owner, platform, DNS owner).
2. Edit the fixture to turn on `block_public_access` for `acme-uploads` and re-run: which finding disappears?
3. Add a new CNAME pointing at a target that is in `existing_targets` and confirm it is not flagged.
4. Explain the difference between an S3 website endpoint origin and an S3 REST origin behind OAC.

## Expected output (real run)

```text
[critical] GCS-PUBLIC-WRITE       acme-shared-writes                 roles/storage.objectCreator granted to allAuthenticatedUsers
[critical] S3-PUBLIC-WRITE        acme-uploads                       anonymous principals may write or delete objects
[critical] CDN-ORIGIN-MISSING     d444-old                           origin 'acme-retired-bucket' does not exist: anyone could register tha
[high    ] S3-ACL-ALLUSERS        acme-marketing-site                legacy ACL grants the AllUsers group
[high    ] S3-PUBLIC-READ         acme-marketing-site                anonymous principals may read objects
[high    ] GCS-PUBLIC-READ        acme-ml-exports                    roles/storage.objectViewer granted to allUsers
[high    ] S3-PUBLIC-READ         acme-public-assets                 anonymous principals may read objects
[high    ] S3-PUBLIC-READ         acme-uploads                       anonymous principals may read objects
[high    ] AZ-BLOB-PUBLIC         acmestorage1/backups               anonymous access level 'container'
[high    ] AZ-SAS-LONG-LIVED      acmestorage1/partner-feed          SAS valid 730 days with 'rwdl'
[high    ] CDN-NO-OAC             d111-assets                        bucket origin is reachable without Origin Access Control/Identity (CDN
[high    ] DNS-DANGLING           docs.acme.example                  CNAME -> acme-docs-site.s3-website.example is not backed by a resource
[high    ] DNS-DANGLING           files.acme.example                 CNAME -> acmeoldfiles.blob.storage.example is not backed by a resource
[medium  ] S3-NO-BLOCK-PUBLIC-ACCESS acme-marketing-site                account/bucket Block Public Access is off
[medium  ] S3-WEBSITE-HTTP        acme-marketing-site                website endpoint is public and HTTP-only; front it with a CDN using HT
[medium  ] S3-NO-BLOCK-PUBLIC-ACCESS acme-public-assets                 account/bucket Block Public Access is off
[medium  ] S3-NO-BLOCK-PUBLIC-ACCESS acme-uploads                       account/bucket Block Public Access is off
[medium  ] AZ-HTTP-ALLOWED        acmestorage1                       secure transfer (HTTPS only) is off
[medium  ] AZ-SHARED-KEY          acmestorage1                       shared key access enabled; prefer Entra ID authorization
[medium  ] CDN-WEBSITE-ORIGIN     d222-site                          website endpoint origin must stay public and cannot use OAC
[low     ] GCS-FINE-GRAINED-ACL   acme-ml-exports                    uniform bucket-level access is off (object ACLs possible)
[low     ] GCS-NO-PAP             acme-ml-exports                    public access prevention is not enforced
[low     ] GCS-NO-PAP             acme-shared-writes                 public access prevention is not enforced
[low     ] S3-NO-ENCRYPTION       acme-uploads                       default encryption not set
[low     ] S3-NO-VERSIONING       acme-uploads                       no versioning: overwritten objects cannot be recovered
{'critical': 3, 'high': 10, 'medium': 7, 'low': 5}
```

## Real-tool guide (hedged)

```text
# AWS (own account only; verify syntax)
aws s3api get-public-access-block --bucket <bucket>
aws s3api get-bucket-policy-status --bucket <bucket>
aws s3control get-public-access-block --account-id <account>
# Azure
az storage account show -n <account> --query "{publicBlob:allowBlobPublicAccess, https:enableHttpsTrafficOnly, sharedKey:allowSharedKeyAccess}"
# GCP
gcloud storage buckets describe gs://<bucket> --format="yaml(iamConfiguration,default_acl)"
gcloud storage buckets get-iam-policy gs://<bucket>
```
Posture tools (Prowler, ScoutSuite, CSPM services) automate these checks for your own accounts; verify they are maintained and read-only. Do not scan or access buckets you do not own.
