# Lab: Securely store encryption keys and other secrets with a Vault/Consul-style server

**Course exercise:** [CDE 8] "Securely store Encryption keys and other secrets using Vault/Consul". Lessons: [lesson 04](../../04-vault-and-consul.md).

**Time:** 60 minutes. **Safety:** everything runs in one Python process. The optional HTTP wrapper binds **127.0.0.1** on a random free port and exists only while a test or demo runs. Secrets are canary strings. Tokens are generated at run time.

> **TEACHING ONLY, NOT REAL CRYPTO.** The cipher in [mini_vault.py](mini_vault.py) is an HMAC-SHA256 keystream with an HMAC tag, written with the standard library to show the *ideas* (authenticated encryption, nonces, key versions). It is not Vault. Use real Vault or OpenBao, and AES-GCM or ChaCha20-Poly1305 from a vetted library, for anything real.

## What MiniVault does

| Area | Behaviour (mirrors the real API shape) |
|---|---|
| **Seal** | `initialize` returns a root token and an unseal key; `seal` wipes the barrier key from memory (everything returns 503); `unseal` restores it |
| **Storage** | A `ConsulLikeKV` (modify index, check-and-set) or `RaftIntegratedStorage` backend. Vault encrypts **before** storing; tests assert the backend holds only ciphertext |
| **Auth** | Root and child tokens with TTL, `renew-self` capped at max TTL, `revoke-self`, AppRole login with a single-use `secret_id` |
| **Policies** | Path ACLs with `create/read/update/delete/list/deny`, `*` suffix and `+` segment wildcards, deny wins, child tokens cannot exceed the parent |
| **KV v2** | `secret/data/...` versions, `cas`, soft delete, `undelete`, `destroy`, `max_versions`, `metadata`, list |
| **Transit** | `encrypt`, `decrypt`, `rewrap`, `rotate`, context binding. The key is created and kept server-side; **there is no way to read it**, and tests assert the application never receives it |
| **Dynamic secrets** | `database/creds/<role>` creates a user in a fake database with a lease; renew (capped), revoke, automatic expiry |
| **Audit** | Method, path, status, HMAC'd token accessor and request key names. Never values, never raw tokens |

## Steps

```text
.venv/Scripts/python devsecops-course/13-secrets-management/labs/vault-consul-secrets/demo.py
.venv/Scripts/python -m pytest devsecops-course/13-secrets-management/labs/vault-consul-secrets -v
```

1. Run the demo and follow numbers 1 to 8.
2. In `demo.py`, give the app policy only `transit/encrypt/orders` and observe that decrypt now returns 403 (separation of duties).
3. Rotate the transit key (`POST transit/keys/orders/rotate`), then decrypt an old ciphertext and `rewrap` it.
4. Change `ConsulLikeKV` to `RaftIntegratedStorage` in `bootstrap` and confirm nothing else changes.
5. Break it on purpose: store a secret and `grep` the backend dump for the canary. What do you find? What does the storage layer still learn (key paths, sizes, timing)? Real Vault hides paths too.

## Expected output (real run)

```text
1. Admin sets up policies, a KV secret, a transit key and a database role
2. The app logs in with AppRole and gets a short-lived token
   policies: ['app-kv', 'app-crypto', 'app-db']
3. The app reads KV v2 (latest version) and an old version
   latest: CANARY-db-password-v2 | version 1: CANARY-db-password-v1
   other/secret -> 403 ['permission denied']
4. Transit: the app encrypts and decrypts without ever holding the key
   ciphertext: vault:v1:zH9nlFZz+KVUFtBU0bVfsEblmWgGvcr...
   plaintext : card ending 4242
   key bytes appear in anything the app received? False
5. Dynamic database credentials with a lease
   user v-readonly-259cc709, lease 300s, login ok: True
   after 301 seconds, login ok: False (Vault dropped the user)
6. The storage backend (Consul-like) sees only ciphertext
   keys stored: 8 | plaintext canary visible: False
7. Seal: the barrier key leaves memory
   status for a valid token: 503
   unseal ok: True
8. Audit log has paths and HMAC'd accessors, never values
   {'time': 1700000301.0, 'method': 'GET', 'path': 'secret/data/app/db', 'status': 503, 'accessor_hmac': '46c238c95d4c', 'request_keys': [], 'policies': ['app-kv', 'app-crypto', 'app-db']}
```

## Run the real tool

`vault server -dev` (or OpenBao `bao server -dev`), KV v2, policies, transit, database and AppRole: [real-tools/vault-openbao.md](../../real-tools/vault-openbao.md). Compare with the earlier [CMCPSE secrets-vault lab](../../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/secrets-vault/README.md).
