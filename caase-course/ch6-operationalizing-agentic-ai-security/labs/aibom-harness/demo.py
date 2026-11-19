import json
from pathlib import Path

import aibom

here = Path(__file__).parent / "harness"
manifest = json.loads((here / "harness.json").read_text())
bom = aibom.build_aibom(manifest, here)
print("serial:", bom["serialNumber"])
for c in bom["components"]:
    kind = next(p["value"] for p in c["properties"] if p["name"] == "caase:kind")
    h = c.get("hashes", [{}])[0].get("content", "-")[:12]
    print(f"  {kind:<11} {c['name']:<20} {c['version']:<12} sha256={h}")
print("validation problems:", aibom.validate(bom))
(Path(__file__).parent / "aibom.cdx.json").write_text(json.dumps(bom, indent=2), encoding="utf-8")
bad = json.loads(json.dumps(bom))
bad["components"][1]["version"] = "latest"
print("after pinning removed:", aibom.validate(bad))
