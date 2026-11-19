import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import headers as hd  # noqa: E402

for name, origin in [("legacy_api_response.json", "https://evil.attacker.test"),
                     ("hardened_api_response.json", "https://shop.example")]:
    h = json.loads((HERE / "fixtures" / name).read_text())
    found = hd.analyze(h, request_origin=origin)
    print(f"== {name}: {len(found)} finding(s)")
    for f in found:
        print(f"  [{f.severity}] {f.id} {f.message}")
    print()

print("CORS origin checks (vulnerable regex vs exact allowlist):")
for o in ["https://shop.example", "https://shop.example.attacker.test", "https://evilshop.example", "null"]:
    print(f"  {o:38} regex={hd.cors_vulnerable_regex(o)!s:5} reflect={hd.cors_vulnerable_reflect(o)!s:5} secure={hd.cors_secure(o)}")

print("\nSameSite model: is the session cookie sent?")
for ss, sec in [("Strict", True), ("Lax", True), ("None", True), ("None", False)]:
    row = {r: hd.cookie_sent(ss, sec, r) for r in ("same-site", "cross-site-top-level-get", "cross-site-post", "cross-site-subresource")}
    print(f"  SameSite={ss:6} Secure={sec!s:5} {row}")

print("\nStrict CSP for a fresh nonce:", hd.build_strict_csp("FRESHNONCE"))
