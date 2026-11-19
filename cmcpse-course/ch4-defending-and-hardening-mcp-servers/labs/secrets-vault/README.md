# Lab: integrate a secrets vault with an MCP server

**Course exercise:** Integrate a secrets vault with an MCP server · **Lesson:** [05 Secrets management](../../05-secrets-management.md) · **Related:** [Module 06, runtime security](../../../../06-ai-devsecops/runtime-security/README.md)

Offline. A **mock vault** (an in-process HTTP server on `127.0.0.1`, free port) imitates the shape of a few Vault HTTP API calls: AppRole login, KV read, dynamic database credentials with leases, renew and revoke. The MCP server fetches secrets **at call time**, never puts them in a schema or the environment, and redacts them from logs. Tests: `test_secrets_vault.py` (15, about 3 seconds).

| File | Role |
|---|---|
| [`mock_vault.py`](mock_vault.py) | `MockVault`: AppRole (with one-time `secret_id`), policies, KV versions, dynamic DB creds with TTL and leases, `rotate_kv()`, injectable clock |
| [`vault_mcp_server.py`](vault_mcp_server.py) | `VaultClient`, `Redactor`, and `SecretsServer` with tools `run_report` (dynamic DB credentials) and `sync_partner` (static API key) |
| [`demo.py`](demo.py) | Fetch, cache, early renewal, rotation, redacted logs |

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/secrets-vault/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/secrets-vault
```

Real demo output (the username differs on each run):

```text
tools/list has secrets?    False
run_report                 report for 2026-10 generated as v-2e428539
sync_partner               catalogue synchronised
DB creds fetched so far    1 (cached within the lease)
after 100s (lease 120s)    2 fetches: renewed early
after rotating the key     catalogue synchronised
log (redacted):
    tool=run_report ok
    tool=sync_partner ok
    tool=run_report ok
    tool=sync_partner ok
    debug: key=[REDACTED] password=[REDACTED]
```

What the tests prove: AppRole login gives a scoped short-lived token; a wrong or replayed one-time `secret_id` fails; policies limit paths; `tools/list` and `os.environ` contain no secret; logs never contain secret values; credentials are cached then replaced before the lease ends; a **revoked lease** and a **rotated static key** are handled; an unreachable vault **fails closed** with a generic message; unexpected exception text never reaches the model.

## Optional: a real HashiCorp Vault dev server (hedged, not run by the repo author)

Dev mode is **in-memory, HTTP only, and prints a root token. Use it on your laptop for learning, never in production.** Verify commands in the current Vault docs.

```bash
vault server -dev                       # note the Root Token and VAULT_ADDR (default http://127.0.0.1:8200)
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<root token printed above>
vault kv put -mount=secret partner api_key=pk-demo-123          # KV v2 is mounted at secret/ in dev mode
vault auth enable approle
vault policy write mcp-reporting - <<'EOF'
path "secret/data/partner" { capabilities = ["read"] }
EOF
vault write auth/approle/role/report-server token_policies="mcp-reporting" token_ttl=5m secret_id_num_uses=1
vault read auth/approle/role/report-server/role-id
vault write -f auth/approle/role/report-server/secret-id
```

Optional `hvac` client (`pip install hvac`, not required by the tests):

```python
import hvac
client = hvac.Client(url="http://127.0.0.1:8200")
client.auth.approle.login(role_id=ROLE_ID, secret_id=SECRET_ID)        # sets client.token
data = client.secrets.kv.v2.read_secret_version(path="partner", mount_point="secret")["data"]["data"]
# dynamic database credentials need the database secrets engine and a real database: see the Vault tutorial
```

Replace `VaultClient` in `vault_mcp_server.py` with these calls and keep the same rules (no env, no schema, redact, fail closed).

## Your tasks

1. Add a policy that lets the server read `kv/partner` but not `kv/unrelated` and prove it with a test (the lab already does the reverse for a second role).
2. Make the vault token renewable: add `POST /v1/auth/token/renew-self` to the mock and renew at 80 percent of the TTL instead of failing at expiry.
3. Add `jwt` login to the mock: accept a signed token from a "CI issuer". Discuss why this removes the stored `secret_id`.
4. Add a fingerprint log: `sha256(secret)[:8]` instead of the value. Why is that useful in an incident?
