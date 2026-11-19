"""Demo: scan an SBOM against a local OSV-format DB."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bomber_lite as b  # noqa: E402

res = b.scan(b.SBOM)
for v in res["vulnerabilities"]:
    print(f"[{v['severity']:8}] {v['package']:18} {v['id']} fixed in {v['fixed']}")
print("unmatched components (no purl):", res["unmatched_components"])
print("summary:", b.summary(res), "| exit code:", b.exit_code(res))
print("ignoring the critical id -> exit", b.exit_code(b.scan(b.SBOM, ignore_ids={"EXAMPLE-OSV-0002"}), "CRITICAL"))
