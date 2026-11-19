"""Demo: SAST stage on a vulnerable and a fixed app, with a baseline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sast_stage as s  # noqa: E402

r = s.run_stage({"app.py": s.VULNERABLE_APP})
print("vulnerable app ->", r["status"])
for f in r["findings"]:
    print(f"  [{f['level']:8}] {f['ruleId']} line {f['line']:2} {f['message']}")
print("fixed app      ->", s.run_stage({"app.py": s.SAFE_APP})["status"])
base = {s.fingerprint(f) for f in r["findings"]}
shifted = "# a comment shifts every line number\n" + s.VULNERABLE_APP
print("legacy code with baseline ->", s.run_stage({"app.py": shifted}, baseline=base)["status"])
extra = shifted + "\ndef more(x):\n    return exec(x)\n"
print("a NEW eval added          ->", s.run_stage({"app.py": extra}, baseline=base)["status"])
