import json
import pathlib

import resolver as r

reg = r.Registry(json.loads((pathlib.Path(__file__).parent / "fixtures" / "registry.json").read_text()))
ROOT = {"web-framework": "^2.0.0", "report-gen": "~1.3.0"}  # the team froze report-gen on 1.3.x

print("App needs:", ROOT)
flat = r.resolve_flat(reg, ROOT)
print("\n1. flat resolve ->", "OK" if flat.ok else "FAILED")
print("  ", flat.conflicts[0].explain())

print("\nStrategy comparison (diamond on json-lib; json-lib < 2.1.0 has an advisory):")
print(f"{'strategy':36} {'ok':5} vuln violated dup  note")
for row in r.compare_strategies(reg, ROOT, "json-lib", "1.9.0", "^2.0.0", "report-gen"):
    print(f"{row['strategy']:36} {row['ok']!s:5} {row['vulnerable']:4} {row['violated_ranges']:8} "
          f"{row['duplicates']:3}  {row['note'][:70]}")

nested = r.resolve_nested(reg, ROOT)
print("\nnested install duplicates:", nested.duplicates())

fixed = r.resolve_flat(reg, {**ROOT, "report-gen": "==1.5.0"})
lock = r.make_lockfile(reg, fixed)
print("\nlockfile packages:", [(p["name"], p["version"]) for p in lock["packages"]])
reg.packages["json-lib"]["versions"]["2.2.1"] = {"deps": {}}   # a new release appears
print("lockfile install still uses:", dict(r.install_from_lockfile(reg, lock).pairs())["json-lib"])
print("fresh resolve now picks    :", r.resolve_flat(reg, {**ROOT, "report-gen": "==1.5.0"}).versions["json-lib"])
print("vendored staleness         :", r.vendored_staleness(reg, r.vendor(fixed)))
