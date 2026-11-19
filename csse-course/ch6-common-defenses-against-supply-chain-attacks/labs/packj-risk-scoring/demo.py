"""Demo: risk scores for three fixture packages."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk_score as r  # noqa: E402

for name, meta in r.PACKAGES.items():
    k = r.score_package(name, meta)
    print(f"== {name}: {k.score} {k.label} -> {r.policy(k)}")
    for why in k.reasons:
        print("   ", why)
