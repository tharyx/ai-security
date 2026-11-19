"""Demo: heuristic scan of three fixture packages."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guarddog_lite as g  # noqa: E402

for name, pkg in g.SAMPLES.items():
    f = g.scan_package(name, pkg)
    print(f"== {name}: {g.verdict(f)}")
    for x in f:
        print(f"   [{x.severity:8}] {x.rule:30} {x.file:22} {x.detail[:60]}")
