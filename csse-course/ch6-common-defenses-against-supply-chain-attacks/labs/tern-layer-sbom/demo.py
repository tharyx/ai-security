"""Demo: layer-by-layer report."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import layer_sbom as t  # noqa: E402

for r in t.layer_deltas(t.IMAGE):
    print(f"{r['layer']} [{'base' if r['base'] else 'yours'}] {r['created_by']}")
    print("   +", r["added"], "- ", r["removed"], "~", r["changed"])
print("attribution:", {k: v["layer"] for k, v in t.attribution(t.IMAGE).items()})
print("base vs added:", t.base_vs_added(t.IMAGE))
print("layers with no package change:", t.layers_without_packages(t.IMAGE))
print("removed later but still in history:", t.deleted_but_present_in_history(t.IMAGE))
