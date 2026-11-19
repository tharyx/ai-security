# Lesson 02: Cloud secret managers and version control

> **Unofficial companion.** Prices, limits and features change. **Verify at the source.**

**Syllabus items:** [CDE 8] Secret Management in Cloud; Version Control systems and Secrets.

## 1. Secret management in the cloud

Each major cloud ships a managed secrets service. They are the easy default when your workloads already run there.

| Service | Highlights (verify) |
|---|---|
| **AWS Secrets Manager** | Versioned secrets with staging labels (`AWSCURRENT`, `AWSPREVIOUS`), **built-in rotation** through Lambda functions (native for RDS and some others), IAM policies and resource policies, KMS encryption, CloudTrail audit, cross-region replication. A cheaper sibling, **SSM Parameter Store**, stores config and `SecureString` values. |
| **Azure Key Vault** | Stores secrets, keys and certificates; access via Entra ID (RBAC or access policies), managed identities, soft delete and purge protection, Event Grid for expiry notifications, HSM-backed tiers. |
| **GCP Secret Manager** | Versions, IAM per secret, automatic or user-managed replication, Cloud Audit Logs, rotation schedule with Pub/Sub notifications (you implement the rotation). Cloud KMS holds keys. |

What they have in common, and how to use them well:

- **Identity, not passwords, to reach secrets.** Use the platform identity (IAM role, managed identity, service account / workload identity) so the workload has no "secret to get the secrets" (the **bootstrap problem**).
- **Least privilege per secret** (resource-scoped permissions, not `*`).
- **KMS/CMK encryption**, and separate who administers the key from who reads the secret.
- **Audit logs on**, with alerts for unusual reads (CloudTrail, Activity Log, Cloud Audit Logs).
- **Rotation**: automate where the service supports it; otherwise own the rotation job. Design apps to re-read a secret or handle a changed one (versions, `AWSPREVIOUS` overlap).
- **Soft delete / recovery windows** so an accidental delete is not an outage; but also know that deleted data may persist for a window.
- **Network**: private endpoints, no public access where possible.
- **Cost and limits**: per-secret and per-call charges; cache values in the client for short periods.

**Cloud manager versus Vault.** Cloud managers are simple and tightly integrated with their own IAM, but they lock you to one cloud and mostly give you static secrets with optional rotation. Vault/OpenBao gives a **uniform API across clouds and on-prem**, **dynamic secrets**, transit encryption, PKI and a rich policy model, at the price of running and securing it (or paying for a managed offering). Many organisations combine them: the cloud manager for cloud-native apps, Vault for multi-cloud and dynamic credentials, with **External Secrets Operator** bridging to Kubernetes (lesson 01).

Link: [CSSE chapter 5: attacking the cloud supply chain](../../csse-course/ch5-attacking-cloud-supply-chain/README.md) shows what happens when cloud credentials leak (metadata services, over-permissive roles).

## 2. Version control systems and secrets

Git remembers everything. A secret committed once is in history, in every clone and fork, in CI caches, in IDE indexes, and possibly in a public mirror within minutes.

### How secrets get into repositories

- A developer commits a `.env`, a `config.json` or a test credential.
- A key is pasted into code "just for testing".
- A **Docker or Terraform state file** is committed.
- Secrets in CI config (`.gitlab-ci.yml`, workflow files).
- Notebook outputs, screenshots, logs.
- Third-party code or history imported from elsewhere.

### Prevention: three layers

| Layer | Tooling | What it stops |
|---|---|---|
| **Developer machine** | pre-commit hooks with gitleaks, detect-secrets, TruffleHog; `.gitignore` for `.env`; editor warnings | The commit never happens (ideal) |
| **Server side** | **Push protection** in GitHub/GitLab, pre-receive hooks | The push is blocked (bypassable by admins; log it) |
| **Pipeline and history** | CI secret scanning of every PR, periodic full-history scans of all repos (TruffleHog verifies whether a secret is live; gitleaks is fast; detect-secrets uses a baseline) | Catches what slipped through |

Old tools such as **gitrob** are unmaintained; use TruffleHog, gitleaks or detect-secrets (verify current status). See [chapter 05](../05-static-analysis-and-secrets/README.md) and the [TruffleHog lab](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md) and [Trivy secrets lab](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md).

### What to do after a leak (the order matters)

1. **Revoke or rotate the secret first.** This is the only step that actually closes the door. Treat the secret as compromised from the moment it was pushed, even to a private repo.
2. **Find out whether it was used**: check provider audit logs (cloud trail, API logs, DB logins) for the exposure window.
3. **Replace it** everywhere it is consumed (use the secrets manager so this is one change).
4. **Remove it from history only as a second step**: `git filter-repo` or BFG, then force-push and ask everyone to re-clone. Remember forks, clones, CI caches, and the hosting provider's cached views (you may need the provider's support to purge).
5. **Add a guardrail** so it cannot recur (pre-commit, push protection, secret-scanning CI).
6. **Write it up** (blameless): how did it get there, why did controls not catch it, what changed.

> Deleting the file in a new commit does nothing for history. Rewriting history without rotation leaves the secret valid. **Rotation is the fix; history cleanup is hygiene.**

### Git hygiene for secrets

- Never use real secrets in tests or docs; use fixtures with obviously fake values (canaries).
- Keep `.env.example` with placeholders, not values.
- Use environment-specific secret stores, not per-environment files in the repo.
- Sign commits and protect branches ([CSSE ch2: commit signing](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md)).
- Encrypt in-repo secrets only with a managed key (SOPS + KMS, Sealed Secrets), never with a shared password in a file.

## Practice

1. Run the [Trufflehog-style lab](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md) and write the rotation checklist for the first finding.
2. For your cloud, write down: how does a pod/VM get its identity, and which one policy lets it read exactly one secret?
3. Continue with [lesson 03](03-env-vars-config-files-and-immutable-systems.md).
