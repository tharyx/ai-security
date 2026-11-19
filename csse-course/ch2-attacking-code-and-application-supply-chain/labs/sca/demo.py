import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sca  # noqa: E402

deps, adv = sca.load(HERE / "fixtures" / "requirements.lock", HERE / "fixtures" / "advisories.json")
findings = sca.scan(deps, adv)
for f in findings:
    kind = "direct" if f.direct else f"via {f.via}"
    print(f"[{f.severity:8}] {f.advisory}  {f.package}=={f.version} ({kind})  fix: {f.fixed_in}  - {f.summary}")
print("gate (fail on high) exit code:", sca.exit_code(findings, "high"))
