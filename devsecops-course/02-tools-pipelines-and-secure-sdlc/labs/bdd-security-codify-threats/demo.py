"""Demo: run the security features against a good app and a vulnerable app."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gherkin_lite as g  # noqa: E402
import security_steps as s  # noqa: E402

FEATURES = Path(__file__).parent / "features"


def run_all(vulnerable):
    total = ok = 0
    for path in sorted(FEATURES.glob("*.feature")):
        res = g.run_text(path.read_text(encoding="utf-8"), s.steps, s.make_context(vulnerable))
        for sc in res.scenarios:
            total += 1
            ok += sc.status == "passed"
            why = next((st.error for st in sc.steps if st.status == "failed"), "")
            tail = ("\n         why: " + why) if why else ""
            print(f"  [{'PASS' if sc.status == 'passed' else 'FAIL'}] {sc.name}{tail}")
    print(f"  -> {ok}/{total} scenarios passed")


print("== hardened app")
run_all(False)
print("\n== vulnerable app")
run_all(True)
