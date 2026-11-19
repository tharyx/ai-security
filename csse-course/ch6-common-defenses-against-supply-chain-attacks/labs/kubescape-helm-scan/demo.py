"""Demo: scan a chart with default values, then with hardened overrides."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import helm_scan as h  # noqa: E402

print("rendered image (defaults):", h.render_chart(h.CHART)[1][0]["spec"]["template"]["spec"]["containers"][0]["image"])
for label, ov in (("default values", None), ("hardened overrides", h.HARDENED_OVERRIDES)):
    f = h.check_chart(h.CHART, ov)
    print(f"== {label}: {len(f)} findings")
    for cid, sev, msg in f:
        print(f"   {cid} {sev:8} {msg}")
