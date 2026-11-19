# Lab: A rules engine for multi-tier and multi-cloud threat models (the IriusRisk pattern, offline)

**Course exercises:** [CTMP 4] "Threat Modeling Multi-Tiered Application with Irius Risk", "Threat Modeling for Multi-Cloud with Irius Risk". Lesson: [02 section 4](../../02-threat-modeling-tools-and-templates.md#4-iriusrisk-multi-tier-and-multi-cloud). Real-tool guide: [IriusRisk walkthrough](../../real-tools/iriusrisk-multi-tier-and-multi-cloud.md).

**Time:** 50 minutes. **Tests:** 7, all offline. **Safety:** fictional projects. Only test systems you own or have written permission to test.

> **Hedge.** IriusRisk is a commercial platform with a free Community Edition (limits change; verify at iriusrisk.com). This lab does **not** imitate its screens or its library. It teaches the **pattern** every rules-based platform uses so the real tool makes sense in minutes. Cloud control names are hedged: check each provider's current documentation.

## Goal

Build two threat models the way IriusRisk does: components on a diagram, answers to a questionnaire, a rules engine that adds threats and countermeasures, countermeasure states, and **inherent versus residual risk**. One model is a multi-tier web application; the other is a multi-cloud pipeline across AWS, Azure and Google Cloud.

## Concept

[iriuslite.py](iriuslite.py) with [fixtures/library.json](fixtures/library.json):

1. **Components** have a type (`web-app`, `rest-api`, `sql-db`, `queue`, `aws-s3`, `azure-blob`, `gcp-gcs`, functions, `cross-cloud-link`) and a trust zone.
2. **Questionnaire** answers set properties (`renders_user_content`, `internet_facing`, `stores_pii`, `uses_static_keys`).
3. **Rules** add a threat when the type and properties match, with countermeasures.
4. **States:** Required, Recommended, Implemented, Not applicable, Rejected. Residual = inherent × (1 − sum of implemented weights).
5. **Report and gate:** totals, reduction, required countermeasures not implemented, and a gate on residual risk above the appetite (12).

**Multi-cloud mapping:** one generic threat, "object storage readable by anyone", gets a provider-specific countermeasure: S3 Block Public Access (AWS), `allowBlobPublicAccess = false` (Azure), public access prevention (Google Cloud). The cross-cloud copy job with static keys gets "workload identity federation (OIDC)".

Fixtures: [multitier.json](fixtures/multitier.json) (Storefront, Orders API, Orders DB, Order events queue) and [multicloud.json](fixtures/multicloud.json).

## Steps

```text
.venv/Scripts/python appsec-course/06-threat-model-tools-reporting-and-ai/labs/rules-engine-multitier-multicloud/demo.py
.venv/Scripts/python -m pytest appsec-course/06-threat-model-tools-reporting-and-ai/labs/rules-engine-multitier-multicloud -q -p no:cacheprovider
```

1. Run the demo. In the multi-tier model the BOLA owner check is still "Required", so residual risk stays at 18 and the gate fails. The queue's countermeasure was "Rejected": the full risk remains, and someone must own that.
2. Set `CM-OWNER@Orders API` to Implemented: residual drops to 2.
3. In the multi-cloud model set the Azure storage and the WIF countermeasures to Implemented. Which threat still blocks?
4. Answer `"stores_pii": false` for the archive bucket: the threat disappears. This is why questionnaire answers must be **honest** and reviewed.

## Expected output (real run of demo.py)

```text
== Multi-tier shop ==
  Storefront                 Cross-site scripting through user content      inherent 16 residual  6.4
      - Implemented    Context-aware output encoding
      - Recommended    Strict CSP with nonces
  Orders API                 Broken object level authorization              inherent 20 residual 18.0
      - Required       Owner check on every object access
      - Implemented    Unguessable ids (defense in depth)
  Orders API                 Unrestricted resource consumption              inherent 12 residual  3.6
      - Implemented    Rate limits at the gateway
  Orders DB                  Application account has more privileges than n inherent 15 residual  4.5
      - Implemented    Least-privilege DB role (no DDL, no DBA)
  Orders DB                  Personal data readable from disks or backups   inherent 15 residual  3.0
      - Implemented    Encryption at rest (TDE) and encrypted backups
  Order events               Unauthenticated producers inject messages      inherent 12 residual   12
      - Rejected       Per-service credentials and topic ACLs
  total inherent 90, residual 47.5 (47.2% reduced)
  required but not implemented: ['CM-OWNER@Orders API (Owner check on every object access)']
  gate (max residual 12) exit code: 1

== Multi-cloud analytics pipeline ==
  Raw uploads (AWS)          Object storage readable by anyone              inherent 20 residual  4.0
      - Implemented    S3 Block Public Access (account and bucket level)
      - Required       SSE-KMS with a customer managed key
  Ingest function (AWS)      Function identity can do far more than its job inherent 15 residual  4.5
      - Implemented    Dedicated execution role with scoped IAM policy
  Curated data (Azure)       Object storage readable by anyone              inherent 20 residual   20
      - Required       Storage account allowBlobPublicAccess = false
      - Required       Customer-managed key in Key Vault
  Scoring function (Azure)   Function identity can do far more than its job inherent 15 residual  4.5
      - Implemented    Managed identity with scoped RBAC role
  Archive (Google Cloud)     Object storage readable by anyone              inherent 20 residual  4.0
      - Implemented    Public access prevention enforced on the bucket
      - Required       CMEK with Cloud KMS
  AWS to Azure copy job      Long-lived cloud keys copied between providers inherent 20 residual   20
      - Required       Workload identity federation (OIDC) instead of static keys
      - Required       Rotate and vault any key that must remain
  total inherent 110, residual 57.0 (48.2% reduced)
  required but not implemented: ['CM-KMS@Raw uploads (AWS) (SSE-KMS with a customer managed key)', 'CM-NOPUBLIC@Curated data (Azure) (Storage account allowBlobPublicAccess = false)', 'CM-KMS@Curated data (Azure) (Customer-managed key in Key Vault)', 'CM-KMS@Archive (Google Cloud) (CMEK with Cloud KMS)', 'CM-WIF@AWS to Azure copy job (Workload identity federation (OIDC) instead of static keys)', 'CM-ROTATE@AWS to Azure copy job (Rotate and vault any key that must remain)']
  gate (max residual 12) exit code: 1
```

## Run the real tool (hedged)

Follow [real-tools/iriusrisk-multi-tier-and-multi-cloud.md](../../real-tools/iriusrisk-multi-tier-and-multi-cloud.md): create a project, draw the same components and trust zones, answer the questionnaire, review generated threats and countermeasures, set states, compare inherent and residual risk, and export the report. The CMCPSE course has another [IriusRisk walkthrough](../../../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/iriusrisk-walkthrough.md) for an MCP deployment.

## What you learned

- Rules-based tools turn component types plus answers into threats and countermeasures; garbage answers give garbage models.
- Inherent versus residual risk makes progress visible; "Rejected" and "Not applicable" need an owner and a reason.
- Multi-cloud threat modeling = generic threats + provider-specific controls + the links **between** clouds.
