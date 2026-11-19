# Lab: Using a Vault-like store to create and consume secrets safely

**Course items:** "Securely Store Secrets Using Hashicorp Vault", "Using HashiCorp Vault To Create and Consume Secrets Safely". Lesson: [03 secrets, data security and TLS](../../03-secrets-data-security-and-tls.md). Real Vault/OpenBao: [real-tools/hashicorp-vault.md](../../real-tools/hashicorp-vault.md). The fuller Vault model (seal, barrier encryption, Transit, Consul/Raft) is [devsecops ch13 vault-consul-secrets](../../../../devsecops-course/13-secrets-management/labs/vault-consul-secrets/README.md); this lab focuses on how an **API service** consumes secrets.

**Time:** 50 minutes. **Tests:** 8, all offline. **Safety:** one Python process; all secrets, tokens and role ids are FAKE and generated at runtime. Only test systems you own or have written permission to test.

## Goal

Compare two ways an orders API gets its database password and its payment-provider API key:

| | `HardcodedOrdersService` (vulnerable) | `VaultOrdersService` (secure) |
|---|---|---|
| Where the secret lives | Config dict (in reality: repo, image, env file) | Vault-like store, read at runtime |
| Identity | None: whoever has the file has the secret | AppRole login (`role_id` + **single-use** `secret_id`) → token with policy and TTL |
| Least privilege | Same password everywhere | Policy allows `secret/data/orders/*` and `database/creds/orders-rw` only |
| DB credentials | One static user | **Dynamic** user per instance with a **lease**, renewed by heartbeat, dropped on expiry |
| Rotation | Breaks the app (and leaks the password into the error log) | Admin writes KV version 2; the service reads it next time |
| Audit | None | Every access logged with **HMACs** of token and values |

## Run

```text
.venv/Scripts/python appsec-course/15-implementing-api-security-mechanisms/labs/vault-secrets-for-apis/demo.py
.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms/labs/vault-secrets-for-apis -v
```

## Expected output (real run)

```text
1. Hardcoded secret (vulnerable)
   query after rotation: error
   error log: ERROR db connect failed with config={'db_user': 'orders_app', 'db_password': 'FAKE-static-dbpw-...
   secret leaked into log: True

2. Vault-like flow (secure)
   AppRole login ok; token policies: ['orders-svc']
   dynamic DB user: v-orders-rw-2eb2d274 | lease 600 s | query: rows
   payments API key read: FAKE-payme...
   read billing/provider -> 403: permission denied: read on secret/data/billing/provider
   reuse of the single-use secret_id -> 400: invalid role_id or secret_id

3. Rotation without redeploy
   admin writes version 2
   service now reads the new key: True

4. Leases and TTLs
   t=500s heartbeat renewed token and lease; query: rows
   t=4500s (past max TTL): DB user still exists? False | token valid? False

5. Audit log (no plaintext secrets)
   {"time": 0.0, "token": "hmac-sha256:f8c25f18533c85a2", "op": "write", "path": "secret/data/orders/payments", "status": 200, "response": []}
   {"time": 0.0, "token": "hmac-sha256:f8c25f18533c85a2", "op": "write", "path": "secret/data/billing/provider", "status": 200, "response": []}
   {"time": 0.0, "token": "hmac-sha256:4b0afaddeab4eb4a", "op": "login", "path": "auth/approle/login", "status": 200, "response": []}
   {"time": 0.0, "token": "hmac-sha256:4b0afaddeab4eb4a", "op": "read", "path": "database/creds/orders-rw", "status": 200, "response": ["hmac-sha256:3f3ed2455da23820"]}
   {"time": 0.0, "token": "hmac-sha256:4b0afaddeab4eb4a", "op": "read", "path": "secret/data/orders/payments", "status": 200, "response": ["hmac-sha256:950a56e287a6a304"]}
   {"time": 0.0, "token": "hmac-sha256:4b0afaddeab4eb4a", "op": "read", "path": "secret/data/billing/provider", "status": 403, "response": []}
   any secret value in audit log: False
```

## Steps

1. Read section 1: rotation broke the hardcoded service, and its error log now contains the secret. Logs are shipped to many systems (chapter 15 lesson 04), so a secret in a log is a leaked secret.
2. Try to read `billing/provider` with the orders token: 403. Edit the `orders-svc` policy to `secret/data/*` and see why wildcards in policies are dangerous.
3. Reuse the `secret_id`: refused. In real Vault, deliver `secret_id` through a trusted orchestrator (response wrapping) and keep `role_id` in the image or config.
4. Advance the clock past the lease: the database user is dropped. Ask: what does this do to an attacker who copied the password from memory yesterday?
5. Search the audit log for the new payment key: it is not there, but you can still prove **which token** read **which path** and when (HMAC the key you are looking for with the audit key to match).

## What you learned

- Secret managers solve **storage**; you still need **identity** (how the app proves who it is), **policy**, **short TTLs**, **rotation** and **audit**.
- Dynamic secrets shrink the value of a stolen credential to minutes.
- Never log configs, connection strings or secret values; log lease ids and paths instead.

## Run the real tool (hedged)

See [real-tools/hashicorp-vault.md](../../real-tools/hashicorp-vault.md): `vault server -dev` on 127.0.0.1 (lab only), KV v2, an AppRole and the database secrets engine. Vault is BSL-licensed since 2023 and IBM completed its acquisition of HashiCorp in 2025 (verify); **OpenBao** (Linux Foundation) is the open-source fork with a compatible CLI (`bao`). Cloud equivalents: AWS Secrets Manager (with rotation Lambdas), Azure Key Vault, GCP Secret Manager.
