# Lesson 03: Secrets with HashiCorp Vault, Data Security Implementation and TLS

**Syllabus items covered:** "Securely Store Secrets Using Hashicorp Vault", "Data Security Implementation", "Using Transport Layer Security (TLS)", "Using HashiCorp Vault To Create and Consume Secrets Safely" ([CASP 8]).

**Time:** 90 minutes. **Lab:** [vault-secrets-for-apis](labs/vault-secrets-for-apis/README.md). **Real tool:** [real-tools/hashicorp-vault.md](real-tools/hashicorp-vault.md). Concepts (encoding vs encryption, password storage, service credentials) were taught in [chapter 14 lesson 02](../14-api-defenses-data-security-and-headers/02-data-security-and-password-storage.md); Vault internals (seal, Consul/Raft, Transit) in [devsecops ch13 lesson 04](../../devsecops-course/13-secrets-management/04-vault-and-consul.md). This lesson is the **implementation** view for an API team.

## 1. Securely store secrets using HashiCorp Vault

**Short summary of Vault** (details in devsecops ch13):

- A server that stores secrets **encrypted** and hands them out only to authenticated clients that a **policy** allows.
- **Auth methods** prove identity: AppRole (apps), Kubernetes service accounts, cloud IAM (AWS/Azure/GCP), JWT/OIDC (CI pipelines), TLS certificates.
- **Policies** are path-based (`path "secret/data/orders/*" { capabilities = ["read"] }`), deny by default.
- **Secrets engines:** KV v2 (versioned static secrets), **database** (dynamic users with leases), **PKI** (short-lived certificates), **Transit** (encryption as a service), cloud engines (short-lived cloud credentials).
- **Leases and TTLs:** every token and dynamic secret expires; clients renew or re-fetch.
- **Audit devices** log every request with HMAC'd values.

**Licensing (verify):** Vault moved to the Business Source License in August 2023, and IBM completed its acquisition of HashiCorp in 2025. **OpenBao** (Linux Foundation) is the open-source fork with a compatible API. Cloud alternatives: AWS Secrets Manager, Azure Key Vault, GCP Secret Manager.

## 2. Using Vault to create and consume secrets safely

**Creating (admin / platform team):**

1. Enable engines and write **narrow** policies per service (`orders-svc` reads `secret/data/orders/*` and `database/creds/orders-rw` only).
2. Configure an auth method bound to the workload's identity (Kubernetes SA `orders` in namespace `shop`, or an AppRole with CIDR-bound secret ids).
3. Put static secrets in KV v2 with metadata (owner, rotation date); prefer dynamic engines where possible.
4. Rotate root and admin credentials; disable the root token after setup; enable audit devices to two sinks.

**Consuming (application team):**

1. **Authenticate with the platform identity**, never a long-lived token in a file. With Kubernetes, use the Vault Agent sidecar/injector or the Vault Secrets Operator (or CSI provider) so the app reads a file or env var that Vault keeps fresh.
2. **Read at startup, cache in memory, refresh before expiry.** Renew leases; on 403/expiry, re-authenticate.
3. **Handle rotation**: be able to reload credentials without restart (connection pools that re-read secrets).
4. **Never log** secrets, tokens or full configs; log lease ids and paths.
5. **Fail safely** if Vault is unreachable: use cached credentials until expiry, alert, do not fall back to a hardcoded default.
6. In CI/CD use JWT/OIDC auth from the pipeline (GitLab `id_tokens`, GitHub OIDC) instead of storing a Vault token as a CI variable.

## 3. Data security implementation

Turning chapter 14's concepts into implementation tasks:

| Data | Implementation |
|---|---|
| Passwords | Argon2id (or scrypt/bcrypt/PBKDF2) with a library; pepper from Vault/KMS; upgrade on login |
| Highly sensitive fields (PAN, Aadhaar, health data) | Field-level AEAD encryption via **Vault Transit** or KMS envelope encryption; keyed HMAC column for lookup; masked views |
| Payment cards | Prefer **tokenization** by the payment provider so card data never reaches you (PCI DSS v4.0.1 scope reduction) |
| Files and backups | Server-side encryption with customer-managed keys; restricted bucket policies |
| Data in logs and analytics | Redaction at the source (lesson 04), pseudonymization with HMAC |
| Data in transit | TLS everywhere (section 4), mTLS between services |
| Retention | Delete what you do not need; India's DPDP Act and GDPR both require purpose limitation and erasure |
| Keys | Rotation schedule, versioned ciphertexts, separation of duties (app can encrypt, only a batch job can decrypt bulk), audit |

**Vault Transit in two lines** (verify syntax): `vault write transit/encrypt/pan plaintext=$(echo -n "$PAN" | base64)` returns `vault:v1:...`; the app stores that string. `vault write -f transit/keys/pan/rotate` then `transit/rewrap/pan` moves data to the new key version without the app ever seeing the key.

## 4. Using Transport Layer Security (TLS)

**Server side:**

- TLS 1.3 preferred, TLS 1.2 minimum with ECDHE + AEAD suites; no SSLv3/TLS 1.0/1.1; OCSP stapling; HSTS for browser-facing hosts.
- Certificates from a trusted CA, automated with ACME (Let's Encrypt, cert-manager in Kubernetes) or **Vault PKI** for internal services; short lifetimes; monitor expiry.
- Generate configs from Mozilla's SSL Configuration Generator ("intermediate" profile is the usual choice; verify).
- Terminate TLS at the edge **and** re-encrypt to backends, or use a service mesh (Istio, Linkerd) for automatic **mTLS** between services.

**Client side (your API calling others):**

- Always verify certificates and hostnames. `verify=False`, `InsecureSkipVerify: true`, `rejectUnauthorized: false` and trust-all `TrustManager`s are findings.
- Pin to a CA or public key only for very controlled clients (mobile apps, partner links), with a rotation plan.
- Use mTLS client certificates for B2B partners; protect the private key (HSM/Vault).

**Testing:** `testssl.sh`, `sslyze`, `nmap --script ssl-enum-ciphers`, and the offline [devsecops ch06 TLS lab](../../devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks/README.md).

## 5. Scenario: the leaked CI variable

A team stores a Vault **root token** as a masked GitLab CI variable "temporarily" so the pipeline can write secrets. A contractor adds `env | base64` to a debug job; masking does not catch the base64 form, and the job log is visible to all project members. The token never expires.

**Fixes:** remove root tokens after setup; CI authenticates with **GitLab OIDC/JWT** to a role that can only write `secret/data/orders/ci/*` with a 10-minute TTL; protected branches only; audit device alerts on root token use; secret scanning on job logs. Same pattern in the devsecops [secrets lessons](../../devsecops-course/13-secrets-management/README.md).

## 6. Checklist

- [ ] I can describe Vault's auth methods, policies, engines, leases and audit in five sentences.
- [ ] I can list six rules for consuming secrets safely in an API service.
- [ ] I can map sensitive data types to an implementation (hashing, Transit, tokenization, redaction).
- [ ] I can state the TLS baseline for servers and the most common client-side mistake.

## References

- HashiCorp Vault and OpenBao documentation (AppRole, Kubernetes auth, KV v2, database and Transit engines, audit devices).
- OWASP Secrets Management, Cryptographic Storage and TLS cheat sheets; Mozilla Server Side TLS.
- PCI DSS v4.0.1; India DPDP Act 2023 and DPDP Rules (notified Nov 2025, phased in; verify dates).
