# Lab: Deployment Services: CodePipeline, Azure DevOps and Cloud Build

**Lessons:** [02 section 4](../../02-attack-vectors-in-aws.md#4-attacking-application-deployment-services) · [03 section 4](../../03-attack-vectors-in-azure.md#4-attacking-web-apps) · [04 section 4](../../04-attack-vectors-in-gcp.md#4-deployment-services-in-gcp-cloud-build-and-artifact-registry). Chapter guide: [README](../../README.md). Related repo labs: [cloud security track](../../../../cybersecurity-track/10-cloud-security/README.md) (CloudTrail detections, IAM analyzer), [09 enterprise architecture](../../../../09-enterprise-architecture/README.md) (cloud controls).

**Course status:** the chapter 5 syllabus lists no hands-on exercises; this lab is an **extra offline practice**. **Time:** 50 minutes. **Tests:** 11, all offline.

**Safety:** no cloud account, no network, no real credentials. Everything is a fixture or an in-process simulation; keys are FAKE; domains are `.example`. Real-tool commands below are for **your own** accounts only and are hedged: verify them in the provider docs.

## What the offline twin does

`analyzer.py` reads `fixtures/pipelines.json` (five pipelines) and flags **over-privileged service roles**, roles **shared across pipelines**, Azure DevOps service connections **authorized for all pipelines**, **artifact stores writable by non-pipeline principals**, missing **digest verification**, missing versioning, no production **approval**, and secrets in plain variables. `run_pipeline` then **simulates tampering**: an attacker with write access swaps the artifact between build and deploy. Without digest verification the malicious payload (a canary string) is deployed; with it, the deploy aborts.

## Steps

```text
.venv/Scripts/python csse-course/ch5-attacking-cloud-supply-chain/labs/deployment-services/demo.py
.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain/labs/deployment-services -v
```

1. Run the demo: three tamper attempts, three different outcomes.
2. Turn on `digest_verification` for `web-release` and observe that the tamper is detected even though the bucket is still writable by a contractor.
3. Then remove the contractor from `writers`. Which of the two controls is more important? (Both: prevent and detect.)

## Expected output (real run)

```text
[critical] ARTIFACT-STORE-WRITABLE   api-release    non-pipeline principals can write artifacts: dev-team-role, contractor
[critical] ROLE-OVERPRIVILEGED       api-release    codepipeline role 'pipeline-role-shared' has admin-like permissions
[critical] ARTIFACT-STORE-WRITABLE   data-jobs      non-pipeline principals can write artifacts: allAuthenticatedUsers
[critical] ROLE-OVERPRIVILEGED       data-jobs      cloud-build role 'default-cloudbuild-sa' has admin-like permissions
[critical] ARTIFACT-STORE-WRITABLE   mobile-backend non-pipeline principals can write artifacts: Project Contributors
[critical] ROLE-OVERPRIVILEGED       mobile-backend azure-devops role 'sc-subscription-owner' has admin-like permissions
[critical] ARTIFACT-STORE-WRITABLE   web-release    non-pipeline principals can write artifacts: dev-team-role, contractor
[critical] ROLE-OVERPRIVILEGED       web-release    codepipeline role 'pipeline-role-shared' has admin-like permissions
[high    ] ARTIFACT-NO-DIGEST-CHECK  api-release    deploy stage does not verify the artifact digest from the build stage
[high    ] ARTIFACT-NO-DIGEST-CHECK  mobile-backend deploy stage does not verify the artifact digest from the build stage
[high    ] CONNECTION-OPEN-TO-ALL    mobile-backend service connection usable by every pipeline in the project
[high    ] PLAIN-SECRET-VARIABLE     mobile-backend SP_SECRET is a plain pipeline variable; use a secret store
[high    ] ARTIFACT-NO-DIGEST-CHECK  web-release    deploy stage does not verify the artifact digest from the build stage
[high    ] PLAIN-SECRET-VARIABLE     web-release    DEPLOY_TOKEN is a plain pipeline variable; use a secret store
[medium  ] NO-PROD-APPROVAL          api-release    no manual approval before the production stage
[medium  ] ROLE-SHARED               api-release    role 'pipeline-role-shared' shared by web-release, api-release
[medium  ] NO-PROD-APPROVAL          mobile-backend no manual approval before the production stage
[medium  ] ROLE-SHARED               web-release    role 'pipeline-role-shared' shared by web-release, api-release
[low     ] ARTIFACT-NO-VERSIONING    api-release    no object versioning: tampering leaves no previous copy
[low     ] ARTIFACT-NO-VERSIONING    web-release    no object versioning: tampering leaves no previous copy

web-release  attacker=contractor-role        tampered=True  -> deployed; payload=b'CANARY-malicious-build'
data-jobs    attacker=allAuthenticatedUsers  tampered=True  -> deploy aborted: digest mismatch; payload=None
hardened     attacker=contractor-role        tampered=False -> deployed; payload=b'legit-build-v1'
```

## Real-tool guide (hedged)

```text
# AWS (own account; verify)
aws codepipeline get-pipeline --name <pipeline> --query 'pipeline.{role:roleArn,artifactStore:artifactStore}'
aws iam get-role --role-name <pipeline-role>; aws iam list-attached-role-policies --role-name <pipeline-role>
aws s3api get-bucket-policy --bucket <artifact-bucket>
# Azure DevOps: Project settings > Service connections > Security: restrict "grant access to all pipelines"
# GCP
gcloud projects get-iam-policy <project> --flatten="bindings[].members" --filter="bindings.members:cloudbuild"
```
Related repo labs: [06 cicd](../../../../06-ai-devsecops/cicd/README.md) (workflow lint, release gate, deploy approval) and [chapter 6 signing](../../../ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing/README.md).
