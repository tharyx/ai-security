# Real tools: HashiCorp Vault / OpenBao for an API service

> **Hedged guide.** Commands follow the Vault CLI shape; check `vault --help` for your version. OpenBao uses the same API with the `bao` command. **Dev mode is for labs only**: it is unsealed, in-memory, and prints a root token. Bind to 127.0.0.1. Nothing in the course tests needs Vault; the offline twin is the [vault-secrets-for-apis lab](../labs/vault-secrets-for-apis/README.md). Licensing: Vault is BSL since 2023 (verify current terms). The deeper Vault guide in this repo is [devsecops ch13 real-tools](../../../devsecops-course/13-secrets-management/real-tools/vault-openbao.md).

## 1. Start a lab server

```bash
vault server -dev -dev-listen-address=127.0.0.1:8200     # lab only
export VAULT_ADDR=http://127.0.0.1:8200                   # dev mode only; real servers use https
```

## 2. Static secret in KV v2 and a narrow policy

```bash
vault kv put secret/orders/payments api_key="$(openssl rand -hex 16)"   # a random lab value
cat > orders-svc.hcl <<'EOF'
path "secret/data/orders/*"     { capabilities = ["read"] }
path "database/creds/orders-rw" { capabilities = ["read"] }
path "sys/leases/renew"         { capabilities = ["update"] }
EOF
vault policy write orders-svc orders-svc.hcl
```

## 3. AppRole for the service

```bash
vault auth enable approle
vault write auth/approle/role/orders token_policies=orders-svc token_ttl=15m token_max_ttl=1h secret_id_num_uses=1
vault read  auth/approle/role/orders/role-id
vault write -f auth/approle/role/orders/secret-id          # deliver via your orchestrator, ideally response-wrapped
vault write auth/approle/login role_id=... secret_id=...    # returns a client token
```

On Kubernetes prefer the **Kubernetes auth method** (service-account JWT) with the Vault Agent Injector, the Vault Secrets Operator or the CSI provider.

## 4. Dynamic database credentials

```bash
vault secrets enable database
vault write database/config/ordersdb plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:5432/orders" \
  allowed_roles=orders-rw username=vault_admin password=<lab-only>
vault write database/roles/orders-rw db_name=ordersdb default_ttl=10m max_ttl=1h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT ON orders TO \"{{name}}\";"
vault read database/creds/orders-rw                          # new user + lease each time
vault lease renew <lease_id>; vault lease revoke <lease_id>
```

Then `vault write -f database/rotate-root/ordersdb` so only Vault knows the admin password.

## 5. Audit

```bash
vault audit enable file file_path=/var/log/vault_audit.log  # values are HMAC'd by default
```

Ship the audit log to your SIEM and alert on root-token use, policy changes and denied reads of sensitive paths.
