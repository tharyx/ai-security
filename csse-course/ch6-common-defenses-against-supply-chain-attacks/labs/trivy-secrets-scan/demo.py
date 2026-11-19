"""Demo: scan the FAKE-secret fixture tree."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan as s  # noqa: E402

res = s.scan_tree(s.FIXTURE)
for r in res:
    for f in r["Secrets"]:
        print(f"[{f['Severity']:8}] {f['Target']:18} line {f['StartLine']}  {f['RuleID']:18} {f['Match']}")
print("exit code (fail on CRITICAL/HIGH):", s.exit_code(res))
print("exit code with aws rule ignored   :", s.exit_code(s.scan_tree(s.FIXTURE, ignore_ids={"aws-access-key-id", "github-pat", "private-key"})))
