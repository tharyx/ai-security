import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validators as v  # noqa: E402

CASES = [
    ("username", v.weak_username, v.strong_username, "bob'; DROP TABLE users--"),
    ("username", v.weak_username_dollar, v.strong_username, "alice\n"),
    ("username", lambda s: s not in v.RESERVED, v.strong_username,  # reserved-name check without NFKC
     "ａｄｍｉｎ"),  # fullwidth 'admin'
    ("comment", v.weak_comment_blocklist, lambda s: "<" not in s and ">" not in s, "<img src=x onerror=alert(1)>"),
    ("pin", v.weak_pin, v.strong_pin, "411001 OR 1=1"),
]
print(f"{'field':9} | {'input':32} | weak  | strong")
for field, weak, strong, value in CASES:
    print(f"{field:9} | {value!r:32} | {str(weak(value)):5} | {strong(value)}")

print("\nCalendar check: '2026-02-30' regex ok:", bool(v.ISO_DATE.fullmatch("2026-02-30")),
      "| strong_date:", v.strong_date("2026-02-30"))

print("\nSchema validation with an extra 'role' field:")
print(v.validate_form({"username": "alice", "email": "alice@shop.example", "pin": "411001",
                       "quantity": "2", "role": "admin"}))
print(v.validate_form({"username": "alice", "email": "alice@shop.example", "pin": "411001", "quantity": "2"}))

print("\nReDoS: nested quantifier detector")
for p in [r"(a+)+$", r"(\w+\s?)*$", r"([a-z0-9]+)*@", r"[a-z]+$", r"[A-Z]{3}-[0-9]{4}"]:
    print(f"  {p:18} nested={v.has_nested_quantifier(p)}")

print("\nReDoS: time for (a+)+$ on 'a'*n + '!' (grows about 2x per extra 'a')")
for n in (16, 18, 20):
    t = v.time_match(r"(a+)+$", "a" * n + "!")
    print(f"  n={n}: {t * 1000:.1f} ms")
print("  safe a+$ on n=20:", f"{v.time_match(r'a+$', 'a' * 20 + '!') * 1000:.3f} ms")
