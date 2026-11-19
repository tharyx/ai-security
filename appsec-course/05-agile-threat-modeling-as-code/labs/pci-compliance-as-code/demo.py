import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pci_rules as pci  # noqa: E402

FIX = HERE / "fixtures"
rules = pci.load_json(FIX / "pci_rules.json")
waivers = pci.load_json(FIX / "waivers.json")
TODAY = date(2026, 11, 19)  # fixed so the output is repeatable

for name in ("payments_api_weak.json", "payments_api_hardened.json"):
    config = pci.load_json(FIX / name)
    results = pci.evaluate(rules, config, waivers, today=TODAY)
    print(f"== {config['system']} ==")
    for r in results:
        extra = f"  observed={str(r.observed)[:30]} {r.detail[:60]}" if r.status != "PASS" else ""
        print(f"  {r.status:6} {r.requirement:8} {r.title[:58]:58}{extra}")
    print("  gate exit code:", pci.gate(results))
    print()

hardened = pci.load_json(FIX / "payments_api_hardened.json")
results = pci.evaluate(rules, hardened, waivers, today=TODAY)
bundle = pci.evidence_bundle(results, hardened, hardened["system"], "2026-11-19T10:00:00Z")
print("== Audit as code: evidence bundle (first lines) ==")
print("\n".join(json.dumps(bundle, indent=2).splitlines()[:9]))
print("  evidence matches current config:", pci.verify_evidence(bundle, hardened))
hardened["tls"]["min_version"] = "1.0"  # someone changes the config after the scan
print("  after a silent config change:   ", pci.verify_evidence(bundle, hardened))

print("\n== The waiver expires ==")
later = pci.evaluate(rules, pci.load_json(FIX / "payments_api_hardened.json"), waivers, today=date(2027, 4, 1))
print("  ", [f"{r.rule_id} {r.status} ({r.detail})" for r in later if r.rule_id == "PCI-AUTH-04"][0])
print("   gate exit code:", pci.gate(later))
