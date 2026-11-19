"""Demo: image scan with CI flags."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trivy_lite as t  # noqa: E402

r = t.scan(t.DPKG)
print(t.table(r))
print("exit code:", t.exit_code(r))
print("--severity HIGH,CRITICAL --ignore-unfixed ->", [x["VulnerabilityID"] for x in t.scan(t.DPKG, severity=("HIGH", "CRITICAL"), ignore_unfixed=True)])
print("with ignore file for the CRITICAL id      -> exit", t.exit_code(t.scan(t.DPKG, ignore_ids={"EXAMPLE-2026-0202"})))
