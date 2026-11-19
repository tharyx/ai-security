"""Run every exercise against the vulnerable and the secure shop and print a table."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attacks  # noqa: E402
import shop  # noqa: E402

print(f"{'Exercise':30} | {'Vulnerable':10} | {'Secure':10}")
print("-" * 58)
for name, fn in attacks.ALL:
    v_ok, v_ev = fn(shop.VulnerableShop())
    s_ok, s_ev = fn(shop.SecureShop())
    print(f"{name:30} | {'EXPLOITED' if v_ok else 'blocked':10} | {'EXPLOITED' if s_ok else 'blocked':10}")
    print(f"{'':30} |   vuln:   {v_ev}")
    print(f"{'':30} |   secure: {s_ev}")

print()
print("Misconfiguration scan, vulnerable:", shop.misconfig_scan(shop.VulnerableShop()))
print("Misconfiguration scan, secure:    ", shop.misconfig_scan(shop.SecureShop()))
