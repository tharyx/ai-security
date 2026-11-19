"""Demo: validate the five fixtures, then show what the validator says about a damaged copy."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_validate as v  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
print("== the same secure pipeline in five syntaxes")
for name in ["gitlab-ci.yml", "github-actions.yml", "Jenkinsfile", "circleci-config.yml", "travis.yml"]:
    r = v.validate_file(FIX / name)
    print(f"  {name:<20} {r.platform:<9} stages={len(r.stages_found)}/7 issues={len(r.issues)} ok={r.ok}")

print("\n== damaged GitHub workflow (tag instead of SHA, write-all, literal password, no DAST)")
t = (FIX / "github-actions.yml").read_text()
t = t.replace("actions/checkout@0123456789abcdef0123456789abcdef01234567", "actions/checkout@v4", 1)
t = t.replace("permissions:\n  contents: read\n\njobs:", "permissions: write-all\nenv:\n  DB_PASSWORD: hunter2-example\n\njobs:")
t = t.replace("zap-baseline.py", "echo skipped #")
for i in v.validate_text("github-actions.yml", t).issues:
    print(f"  {i.severity:<8} {i.check:<10} {i.message}")
