import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import injection_lab as L  # noqa: E402

c = L.make_db()
print("== SQL injection ==")
for term in ("bo", "' OR hidden = 1 --", "' UNION SELECT name, password FROM users --"):
    print(f"term={term!r}")
    print("   vulnerable:", L.search_vuln(c, term))
    print("   bind vars :", L.search_safe(c, term))

print("\n== ORM injection through order_by ==")
v, s = L.MiniORM(c, secure=False), L.MiniORM(c, secure=True)
print("normal sort -price :", s.products(order_by="-price"))
print("vulnerable ORM: admin password recovered via sort-order oracle ->", L.orm_extract_password(v, len(L.ADMIN_PW)))
try:
    s.products(order_by="(CASE WHEN 1=1 THEN price END)")
except ValueError as e:
    print("secure ORM:", e)

print("\n== NoSQL operator injection ==")
attack = {"username": "admin", "password": {"$ne": ""}}
print("vulnerable login with", attack, "->", (L.nosql_login_vuln(attack) or {}).get("role"))
try:
    L.nosql_login_safe(attack)
except ValueError as e:
    print("secure login ->", e)

print("\n== SSRF via a link-preview feature (FAKE network) ==")
for url in ("https://images.partner.example/cat.png", "http://169.254.169.254/latest/meta-data/",
            "https://metadata.attacker.example/", "http://2852039166/"):
    try:
        safe = L.preview_safe(url)
    except ValueError as e:
        safe = f"blocked ({e})"
    print(f"{url}\n   vulnerable: {L.preview_vuln(url)}\n   secure    : {safe}")
