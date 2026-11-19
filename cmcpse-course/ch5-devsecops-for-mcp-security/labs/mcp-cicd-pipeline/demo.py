"""Demo: run the MCP security pipeline on a clean project and on a compromised pull request."""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pipeline_runner", HERE / "pipeline_runner.py")
pr = importlib.util.module_from_spec(spec)
sys.modules["pipeline_runner"] = pr
spec.loader.exec_module(pr)

for project in ("project-good", "project-bad"):
    print(f"\n===== {project} =====")
    result = pr.run_pipeline(HERE / "fixtures" / project)
    print(pr.format_report(result))
    print("exit code:", result.exit_code)

print("\n===== workflow fixture lint =====")
print(pr.lint_workflow(HERE / "fixtures" / "mcp-security.yml") or "no problems")
