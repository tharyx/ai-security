# Lab: Serverless Supply Chain: Lambda, Azure Functions, Cloud Functions

**Lessons:** [02 section 3](../../02-attack-vectors-in-aws.md#3-attacking-serverless-computing) · [03 section 3](../../03-attack-vectors-in-azure.md#3-attacking-azure-functions) · [04 section 3](../../04-attack-vectors-in-gcp.md#3-attacking-google-cloud-functions). Chapter guide: [README](../../README.md). Related repo labs: [cloud security track](../../../../cybersecurity-track/10-cloud-security/README.md) (CloudTrail detections, IAM analyzer), [09 enterprise architecture](../../../../09-enterprise-architecture/README.md) (cloud controls).

**Course status:** the chapter 5 syllabus lists no hands-on exercises; this lab is an **extra offline practice**. **Time:** 50 minutes. **Tests:** 12, all offline.

**Safety:** no cloud account, no network, no real credentials. Everything is a fixture or an in-process simulation; keys are FAKE; domains are `.example`. Real-tool commands below are for **your own** accounts only and are hedged: verify them in the provider docs.

## What the offline twin does

`audit.py` reads `fixtures/functions.json` (four functions across the three clouds) and checks **environment-variable secrets** (name and value patterns; secret-manager references are accepted), **layers** (untrusted account, unpinned version), **dependencies** (advisories with numeric version compare, known-malicious list, missing hash), **execution roles** (wildcards, broad built-in roles, `iam:PassRole` and similar escalation actions) and **unauthenticated triggers**, plus a one-line blast radius per function.

## Steps

```text
.venv/Scripts/python csse-course/ch5-attacking-cloud-supply-chain/labs/serverless-supply-chain/demo.py
.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain/labs/serverless-supply-chain -v
```

1. Run the demo and read the blast radius lines.
2. Fix `orders-api` in the fixture (trust only your layer account, pin the layer, move secrets to a secret manager reference, scope the role) until no findings remain.
3. Which findings are code-supply-chain issues and which are configuration issues?

## Expected output (real run)

```text
[critical] DEP-MALICIOUS       orders-api   colourz-utils is on the known-malicious list
[critical] ROLE-PRIVESC        orders-api   can pass or change roles on any resource: privilege-escalation path
[high    ] ENV-SECRET          export-job   SERVICE_TOKEN looks like a secret stored in an environment variable
[high    ] ROLE-BROAD-BUILTIN  export-job   broad built-in role ['roles/editor']
[high    ] URL-NO-AUTH         export-job   function URL/trigger is callable without authentication
[high    ] DEP-VULNERABLE      orders-api   requests-lite@1.3.0 < 1.4.2 (FAKE-ADV-002)
[high    ] ENV-SECRET          orders-api   DB_PASSWORD looks like a secret stored in an environment variable
[high    ] ENV-SECRET          orders-api   API_KEY looks like a secret stored in an environment variable
[high    ] LAYER-THIRD-PARTY   orders-api   layer fast-json-layer comes from untrusted account 999900001111
[high    ] ROLE-WILDCARD       orders-api   ['s3:*'] on every resource
[high    ] URL-NO-AUTH         orders-api   function URL/trigger is callable without authentication
[high    ] DEP-VULNERABLE      thumbnailer  left-padz@1.2.0 < 2.0.0 (FAKE-ADV-001)
[high    ] ENV-SECRET          thumbnailer  STORAGE_CONNECTION_STRING looks like a secret stored in an environment vari
[medium  ] LAYER-UNPINNED      orders-api   layer fast-json-layer version 'latest' is not pinned
[low     ] DEP-NO-HASH         orders-api   requests-lite has no pinned hash in the build
[low     ] DEP-NO-HASH         orders-api   colourz-utils has no pinned hash in the build

orders-api   blast radius: may escalate to other roles
thumbnailer  blast radius: scoped to its own resources
export-job   blast radius: broad data/resource access
clean-fn     blast radius: scoped to its own resources
```

## Real-tool guide (hedged)

```text
# AWS (own account; verify)
aws lambda get-function-configuration --function-name <name> --query '{env:Environment,layers:Layers,role:Role}'
aws lambda get-function-url-config --function-name <name>
aws iam list-attached-role-policies --role-name <role>
# Azure
az functionapp config appsettings list -g <rg> -n <app>
# GCP
gcloud functions describe <name> --region <region> --format="yaml(serviceAccountEmail,environmentVariables,ingressSettings)"
```
Dependency checks: `osv-scanner`, `trivy fs`, `pip-audit`, `npm audit` on the function's lockfile; see [chapter 6](../../../ch6-common-defenses-against-supply-chain-attacks/README.md).
