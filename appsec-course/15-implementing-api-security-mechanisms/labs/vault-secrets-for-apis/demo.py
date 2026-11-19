import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vault_lite as vl  # noqa: E402

print("1. Hardcoded secret (vulnerable)")
db = vl.FakeDatabase()
pw = vl.fake_secret("static-dbpw")
db.create_user("orders_app", pw)
svc = vl.HardcodedOrdersService(db, {"db_user": "orders_app", "db_password": pw})
db.create_user("orders_app", vl.fake_secret("rotated"))  # DBA rotates the password
print("   query after rotation:", svc.query())
print("   error log:", svc.log[0][:95] + "...")
print("   secret leaked into log:", pw in svc.log[0])

print("\n2. Vault-like flow (secure)")
v, admin, role_id, secret_id = vl.bootstrap()
s = vl.VaultOrdersService(v, role_id, secret_id)
print("   AppRole login ok; token policies:", v.tokens[s.token]["policies"])
print("   dynamic DB user:", s.creds["data"]["username"], "| lease", s.creds["lease_duration"], "s | query:", s.query())
print("   payments API key read:", s.api_key_for_payments()[:10] + "...")
try:
    v.kv_get(s.token, "billing/provider")
except vl.VaultError as e:
    print("   read billing/provider ->", e)
try:
    vl.VaultOrdersService(v, role_id, secret_id)
except vl.VaultError as e:
    print("   reuse of the single-use secret_id ->", e)

print("\n3. Rotation without redeploy")
new_key = vl.fake_secret("payments-v2")
print("   admin writes version", v.kv_put(admin, "orders/payments", {"api_key": new_key}))
print("   service now reads the new key:", s.api_key_for_payments() == new_key)

print("\n4. Leases and TTLs")
v.clock.advance(500); s.heartbeat()
print("   t=500s heartbeat renewed token and lease; query:", s.query())
user = s.creds["data"]["username"]
v.clock.advance(4000); v._expire()
print("   t=4500s (past max TTL): DB user still exists?", user in v.db.users, "| token valid?", s.token in v.tokens)

print("\n5. Audit log (no plaintext secrets)")
for e in v.audit[:6]:
    print("  ", json.dumps(e))
print("   any secret value in audit log:", any(new_key in json.dumps(e) for e in v.audit))
