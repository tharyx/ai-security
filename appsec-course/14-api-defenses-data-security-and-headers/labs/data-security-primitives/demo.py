import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import datasec as d  # noqa: E402

print("1. ENCODING (no key, reversible by anyone)")
enc = d.encode_all("role=admin&user=asha")
for k, v in enc.items():
    print(f"   {k:9} {v}  -> decodes to {d.decode(k, v)!r}")

print("\n2. ESCAPING (one interpreter at a time)")
payload = '</script><img src=x onerror=alert(1)>'
for ctx in ("html", "js_string", "url_param"):
    print(f"   {ctx:9} {d.escape_for(ctx, payload)}")
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (name TEXT, role TEXT)")
db.executemany("INSERT INTO users VALUES (?, ?)", [("asha", "user"), ("ravi", "admin")])
inj = "x' OR '1'='1"
print("   SQL string-built :", d.sql_lookup(db, inj, safe=False))
print("   SQL bind variable:", d.sql_lookup(db, inj, safe=True))

print("\n3. HASHING (one-way, but small inputs can be enumerated)")
h = d.sha256_hex("4821")
print("   sha256('4821')       =", h[:24] + "...")
print("   reversed by brute force ->", d.reverse_low_entropy_hash(h))
key = os.urandom(32)
print("   HMAC pseudonym       =", d.keyed_pseudonym(key, "4821")[:24] + "...  (no key, no enumeration)")

print("\n4. ENCRYPTION AT REST (ToyAEAD: NOT FOR PRODUCTION; use AES-GCM via a vetted library/KMS)")
plain = d.CardStore(encrypted=False)
kr = d.KeyRing(); kr.rotate()
safe = d.CardStore(encrypted=True, keyring=kr)
for i, cid in enumerate(["cust-001", "cust-002"], start=1):
    plain.add(cid, d.fake_pan(i)); safe.add(cid, d.fake_pan(i))
print("   plaintext table dump:\n     " + plain.dump().replace("\n", "\n     "))
print("   encrypted table dump:\n     " + "\n     ".join(line[:70] + "..." for line in safe.dump().splitlines()))
print("   app reads cust-002   :", safe.get_pan("cust-002"))
row1 = safe.db.execute("SELECT pan FROM cards WHERE customer_id='cust-001'").fetchone()[0]
safe.db.execute("UPDATE cards SET pan=? WHERE customer_id='cust-002'", (row1,))
try:
    safe.get_pan("cust-002")
except d.IntegrityError as e:
    print("   ciphertext copied to another row ->", e)
safe.db.execute("DELETE FROM cards WHERE customer_id='cust-002'"); safe.add("cust-002", d.fake_pan(2))
print("   rotate key and rewrap:", safe.rotate_and_rewrap(), "rows now on", kr.active)
