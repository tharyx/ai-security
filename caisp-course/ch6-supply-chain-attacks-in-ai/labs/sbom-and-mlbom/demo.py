"""Demo: build the SBOM + ML-BOM for the fixture environment and show the checks.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/demo.py
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sbom_gen as sg  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> None:
    env = json.loads((HERE / "fixture_env.json").read_text(encoding="utf-8"))
    bom = sg.build_bom(env)
    print(f"bomFormat={bom['bomFormat']} specVersion={bom['specVersion']} serial={bom['serialNumber']}")
    for c in bom["components"]:
        print(f"  {c['type']:24} {c['name']:32} {c.get('version', '')}")
    print("validation problems:", sg.validate_bom(bom) or "none")

    model = next(c for c in bom["components"] if c["name"] == "tiny-support-classifier")
    print("\nML-BOM entry (the model):")
    print(json.dumps(model, indent=2))

    broken = copy.deepcopy(bom)
    next(c for c in broken["components"] if c["name"] == "tiny-support-classifier")["modelCard"][
        "modelParameters"]["datasets"] = []
    print("\nAfter removing the training dataset from the model card:")
    for p in sg.validate_bom(broken):
        print("  PROBLEM:", p)


if __name__ == "__main__":
    main()
