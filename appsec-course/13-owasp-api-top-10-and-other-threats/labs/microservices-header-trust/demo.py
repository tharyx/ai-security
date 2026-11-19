import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mesh as m  # noqa: E402

alice = m.login("alice")
for secure in (False, True):
    print(f"===== {'SECURE' if secure else 'VULNERABLE'} mesh =====")
    print("alice reads her order o-1                     ->", m.gateway({"Cookie": alice}, "/orders/o-1", secure))
    print("alice adds X-User-Id: bob, reads o-2         ->",
          m.gateway({"Cookie": alice, "X-User-Id": "bob"}, "/orders/o-2", secure))
    print("attacker on flat network calls orders directly ->",
          m.orders_service({"X-User-Id": "bob"}, "o-2", secure))
    print("alice adds X-Forwarded-For: 10.0.0.1, GET /admin ->",
          m.gateway({"Cookie": alice, "X-Forwarded-For": "10.0.0.1"}, "/admin", secure))
    print()
