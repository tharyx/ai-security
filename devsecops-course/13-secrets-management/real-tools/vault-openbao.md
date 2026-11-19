# Real tools: Vault dev server and OpenBao

> Hedged guide. Commands change between releases: **verify at developer.hashicorp.com/vault and openbao.org**. HashiCorp Vault is under the BSL licence (Aug 2023); OpenBao is the Linux Foundation fork and uses the `bao` CLI with the same command shapes. Use a **dev server only for learning**: it is in-memory, unsealed, has a known root token and no TLS. Never put real secrets in it. The labs never need these tools.

## Start a dev server (loopback only)

```text
vault server -dev -dev-listen-address=127.0.0.1:8200
# in another terminal
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<the root token printed by the dev server>
vault status
```

OpenBao: replace `vault` with `bao` (`bao server -dev`, `BAO_ADDR`, `BAO_TOKEN`; verify variable names).

## KV v2

```text
vault secrets enable -path=secret kv-v2        # already enabled in dev mode
vault kv put secret/app/db username=orders password=<fake-value>
vault kv get secret/app/db
vault kv put -cas=1 secret/app/db username=orders password=<new-fake-value>
vault kv get -version=1 secret/app/db
vault kv delete secret/app/db
vault kv undelete -versions=2 secret/app/db
vault kv metadata get secret/app/db
```

## Policy and token

```text
vault policy write app-read - <<'EOF'
path "secret/data/app/*" { capabilities = ["read"] }
path "secret/metadata/app/*" { capabilities = ["list"] }
EOF
vault token create -policy=app-read -ttl=15m
```

## Transit

```text
vault secrets enable transit
vault write -f transit/keys/orders
vault write transit/encrypt/orders plaintext=$(echo -n "hello" | base64)
vault write transit/decrypt/orders ciphertext=<the vault:v1:... string>
vault write -f transit/keys/orders/rotate
vault write transit/rewrap/orders ciphertext=<old ciphertext>
vault read transit/keys/orders          # metadata only, no key material
```

## Dynamic database credentials (needs a real database)

```text
vault secrets enable database
vault write database/config/mydb plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:5432/postgres" \
    allowed_roles=readonly username=<admin> password=<admin-password>
vault write database/roles/readonly db_name=mydb \
    creation_statements="..." default_ttl=5m max_ttl=15m
vault read database/creds/readonly
vault lease renew <lease_id>
vault lease revoke <lease_id>
```

Only run this against a throwaway database you own.

## AppRole

```text
vault auth enable approle
vault write auth/approle/role/orders token_policies=app-read token_ttl=10m secret_id_num_uses=1
vault read auth/approle/role/orders/role-id
vault write -f auth/approle/role/orders/secret-id
```

## Production notes (not covered by the dev server)

TLS, integrated Raft storage (or Consul), auto-unseal with a KMS/HSM, at least two audit devices, no long-lived root token, backups with tested restores, network policy, and monitoring of seal status and auth failures.
