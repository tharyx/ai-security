import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scopes as s  # noqa: E402

weak, secure = s.load(HERE / "fixtures/spec_weak.json"), s.load(HERE / "fixtures/spec_secure.json")
clients = s.load(HERE / "fixtures/clients.json")
for spec, cl in ((weak, None), (secure, clients)):
    found = s.lint_spec(spec, cl)
    print(f"== {spec['name']}: {len(found)} finding(s)")
    for f in found:
        print(f"  [{f.severity}] {f.id} {f.message}")
    print()

print("Scope -> endpoint matrix (reviewed spec):")
print(s.matrix(secure))

orders = {"1001": "asha", "1002": "ravi"}
cases = [
    ("asha, read-only token, DELETE her order", {"sub": "asha", "roles": ["customer"], "scope": "orders:read"}, "DELETE", "/orders/1001"),
    ("asha, full token, reads ravi's order", {"sub": "asha", "roles": ["customer"], "scope": "orders:read orders:write"}, "GET", "/orders/1002"),
    ("support agent asks for refunds:admin", {"sub": "meena", "roles": ["support"], "scope": "orders:read refunds:admin"}, "POST", "/admin/refunds"),
    ("finance user issues refund", {"sub": "kiran", "roles": ["finance"], "scope": "refunds:admin"}, "POST", "/admin/refunds"),
    ("undocumented route", {"sub": "asha", "roles": ["customer"], "scope": "orders:read"}, "GET", "/internal/export"),
]
print("\nEnforcement: vulnerable vs secure")
for label, claims, m, p in cases:
    v = s.authorize_vulnerable(claims, m, p, secure, orders.get)
    d = s.authorize_secure(claims, m, p, secure, orders.get)
    print(f"  {label:42} vulnerable={'ALLOW' if v.allow else 'deny':5} secure={'ALLOW' if d.allow else 'deny':5} ({d.reason})")
