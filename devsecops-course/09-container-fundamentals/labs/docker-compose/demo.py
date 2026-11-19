import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import composer

doc = composer.load((Path(__file__).parent / "fixtures" / "compose.yml").read_text())
print("Dependency graph:")
for k, v in composer.graph(doc).items():
    print(f"  {k:<6} depends on {v}")
print("Start order:", " -> ".join(composer.start_order(doc)))
print("\nSecurity review:")
for sev, svc, msg in composer.review(doc):
    if sev != "LOW":
        print(f"  [{sev:<8}] {svc:<6} {msg[:88]}")
print("  ... plus", sum(1 for s, _, _ in composer.review(doc) if s == "LOW"), "LOW items")
