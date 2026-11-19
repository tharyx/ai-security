import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import layerscan as ls

img = ls.sample_image()
eff = ls.efficiency(img)
print(f"Image {img['name']}: total {eff['total']:,} B, visible {eff['visible']:,} B, wasted {eff['wasted']:,} B, efficiency {eff['score']:.1%}")
for l in eff["layers"]:
    print(f"  layer {l['layer']}: {l['size']:>11,} B  wasted {l['wasted']:>11,} B  {l['created_by'][:50]}")
print("\nSecrets (found in layers, even the ones deleted later):")
for s in ls.find_secrets(img):
    state = "still in final fs" if s["still_visible"] else "DELETED later but still in layer"
    print(f"  layer {s['layer']} {s['path']:<22} {s['kind']:<20} {state}")
print("\nVulnerable packages (fixture DB):")
for h in ls.vulnerable_packages(img):
    print(f"  {h['severity']:<9} {h['package']} {h['installed']} < {h['fixed_in']}  ({h['id']})")
