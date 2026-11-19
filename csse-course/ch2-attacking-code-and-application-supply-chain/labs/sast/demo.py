import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scanner  # noqa: E402

for name in ("vulnerable_app.py", "fixed_app.py"):
    findings = scanner.scan_source((HERE / "fixtures" / name).read_text())
    print(f"== {name}: {len(findings)} finding(s), gate exit code {scanner.exit_code(findings)} ==")
    for f in findings:
        print(f"  line {f.line:3} {f.rule} [{f.severity:8}] {f.cwe:8} {f.message}")
