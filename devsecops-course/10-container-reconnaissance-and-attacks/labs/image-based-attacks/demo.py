import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import imgattack as ia

img = ia.sample_image()
print("Secrets an attacker gets without running the image:")
for s in ia.extract_secrets(img):
    print(f"  {s['where']:<18} {s['name']:<22} via: {s['how']}")
print("\nExploit paths (vulnerable components):")
for p in ia.exploit_paths(img):
    print(f"\n[{p.priority}] {p.vuln_id} in {p.component}: reachable={p.reachable} ({p.why})")
    for step in p.steps:
        print("    -", step)
