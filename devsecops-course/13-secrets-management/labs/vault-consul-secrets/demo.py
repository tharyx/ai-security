"""From repo root:
    .venv/Scripts/python devsecops-course/13-secrets-management/labs/vault-consul-secrets/demo.py
"""
import mini_vault as mv

clock = mv.Clock()
backend = mv.ConsulLikeKV()
vault, root, unseal_key = mv.bootstrap(backend, clock)
transport = mv.RecordingTransport(mv.InProcessTransport(vault))
admin = mv.VaultClient(transport, root)

print("1. Admin sets up policies, a KV secret, a transit key and a database role")
admin.call("POST", "sys/policies/acl/app-kv", {"policy": {"secret/data/app/*": ["read"], "secret/metadata/app/*": ["list"]}})
admin.call("POST", "sys/policies/acl/app-crypto", {"policy": {"transit/encrypt/orders": ["update"], "transit/decrypt/orders": ["update"]}})
admin.call("POST", "sys/policies/acl/app-db", {"policy": {"database/creds/readonly": ["read"], "sys/leases/renew": ["update"]}})
admin.kv_put("app/db", {"username": "orders", "password": "CANARY-db-password-v1"})
admin.kv_put("app/db", {"username": "orders", "password": "CANARY-db-password-v2"})
admin.call("POST", "transit/keys/orders")
admin.call("POST", "database/roles/readonly", {"default_ttl": 300, "max_ttl": 900})
admin.call("POST", "auth/approle/role/orders-app", {"policies": ["app-kv", "app-crypto", "app-db"], "token_ttl": 600})
role_id = admin.call("GET", "auth/approle/role/orders-app/role-id")["data"]["role_id"]
secret_id = admin.call("POST", "auth/approle/role/orders-app/secret-id")["data"]["secret_id"]

print("2. The app logs in with AppRole and gets a short-lived token")
app = mv.VaultClient(transport)
app.approle_login(role_id, secret_id)
print("   policies:", app.call("GET", "auth/token/lookup-self")["data"]["policies"])

print("3. The app reads KV v2 (latest version) and an old version")
print("   latest:", app.kv_get("app/db")["password"], "| version 1:", app.kv_get("app/db", version=1)["password"])
try:
    app.kv_get("other/secret")
except mv.VaultError as exc:
    print("   other/secret ->", exc)

print("4. Transit: the app encrypts and decrypts without ever holding the key")
ct = app.encrypt("orders", b"card ending 4242", context="order-1001")
print("   ciphertext:", ct[:40] + "...")
print("   plaintext :", app.decrypt("orders", ct, context="order-1001").decode())
key_b64 = vault._get("transit/orders")["versions"]["1"]["key"]
print("   key bytes appear in anything the app received?", key_b64 in transport.transcript)

print("5. Dynamic database credentials with a lease")
creds = app.db_creds("readonly")
user, pw = creds["data"]["username"], creds["data"]["password"]
print(f"   user {user}, lease {creds['lease_duration']}s, login ok: {vault.database.login_ok(user, pw)}")
clock.advance(301)
vault.request("GET", "sys/seal-status")
print("   after 301 seconds, login ok:", vault.database.login_ok(user, pw), "(Vault dropped the user)")

print("6. The storage backend (Consul-like) sees only ciphertext")
dump = backend.raw_dump()
print("   keys stored:", len(dump), "| plaintext canary visible:", any(b"CANARY" in v for v in dump.values()))

print("7. Seal: the barrier key leaves memory")
vault.seal()
print("   status for a valid token:", app.t("GET", "secret/data/app/db", app.token)[0])
print("   unseal ok:", vault.unseal(unseal_key))

print("8. Audit log has paths and HMAC'd accessors, never values")
print("  ", vault.audit_log[-1])
