"""Demo: audit an insecure and a hardened harness config."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_plugin as p  # noqa: E402

for name in ("insecure", "hardened"):
    r = p.audit(p.load(HERE / "configs" / f"{name}.json"))
    print(f"== {r['name']}: score {r['score']}/100, grade {r['grade']} ==")
    for x in r["results"]:
        mark = "PASS" if x["passed"] else "FAIL"
        print(f"  {mark} {x['id']:7} {x['asi']}  {x['message']}")
    if r["failed"]:
        print("  failures by ASI:", p.by_asi(r))
    print()
