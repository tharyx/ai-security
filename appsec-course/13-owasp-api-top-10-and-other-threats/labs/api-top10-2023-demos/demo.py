import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import top10 as t  # noqa: E402

print("== OWASP API Security Top 10: 2019 -> 2023 ==")
for old, new in t.MAP_2019_TO_2023.items():
    print(f"  {old:<46} -> {new or '(dropped as its own item)'}")
for new in t.NEW_IN_2023:
    print(f"  {'(new)':<46} -> {new}")

print("\n== Same attack against vulnerable and secure mini-APIs ==")
print(f"  {'item':<40} {'vulnerable':<12} secure")
for item, vuln, sec in t.run_all():
    print(f"  {item:<40} {'EXPLOITED' if vuln else 'blocked':<12} {'EXPLOITED' if sec else 'blocked'}")

print("\nAPI9 undocumented endpoints still deployed:", t.api9_undocumented(t.DEPLOYED_VULN))
print("API10 vulnerable query built from partner data:", t.api10_consume(False, "560001")[0])
