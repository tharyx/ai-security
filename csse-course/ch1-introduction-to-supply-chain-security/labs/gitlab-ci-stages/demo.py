"""Demo: check the starter file, then the reference solution."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_checker as sc  # noqa: E402

here = Path(__file__).parent
for label, f in (("starter (your exercise file)", here / "starter.gitlab-ci.yml"),
                 ("reference solution", here / "solutions" / "solution.gitlab-ci.yml")):
    text = f.read_text()
    print(f"== {label}")
    for c in sc.check_all(text):
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.id}  {c.message}")
    print("  columns:", sc.stage_order(text))
