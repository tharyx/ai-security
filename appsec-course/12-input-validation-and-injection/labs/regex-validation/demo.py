import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validators as v  # noqa: E402

print("== Anchoring mistakes ==")
for s in ("alice_01", "alice; DROP TABLE users", "alice\n"):
    print(f"{s!r:<28} re.match={v.weak_match(s)!s:<5} ^...$={v.weak_dollar(s)!s:<5} fullmatch={v.validate(v.USERNAME, s)}")

print("\n== Allowlist vs denylist ==")
for s in ("Nice post!", "<script>x</script>", "<ScRiPt>x</ScRiPt>", "<img src=x onerror=alert(1)>"):
    print(f"{s!r:<32} denylist says safe={v.denylist_filter(s)!s:<5} allowlist accepts={v.allowlist_comment(s)}")

print("\n== Other validators ==")
print("PIN 560001:", v.validate(v.POSTCODE_IN, "560001"), "| PIN 056001:", v.validate(v.POSTCODE_IN, "056001"))
print("date 2026-11-19:", v.validate(v.ISO_DATE, "2026-11-19"), "| date 2026-13-01:", v.validate(v.ISO_DATE, "2026-13-01"))

print("\n== ReDoS ==")
for p in (r"^(a+)+$", r"^(\w*)*@", r"^a+$"):
    print(f"{p:<12} nested-quantifier warning: {v.looks_redos_prone(p)}")
for n in (16, 18, 20):
    print(f"  ^(a+)+$ on 'a'*{n}+'!': {v.time_regex(r'^(a+)+$', n):.3f}s   ^a+$: {v.time_regex(r'^a+$', n):.6f}s")
print("  (each +2 characters roughly x4 time; timings vary per machine)")

print("\n== Client-side check is not a control ==")
evil = "x' OR 1=1 --"
print("browser JS accepts it?", v.client_side_form_check(evil), "-> attacker sends it with curl anyway:")
print("  server without validation:", v.server_create_user(evil, False))
print("  server with validation   :", v.server_create_user(evil, True))

print("\n== Sanitization ==")
print(repr(v.sanitize_display_name("  Ａlice‮  \t Smith\x00 ")))
