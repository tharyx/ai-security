import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gitlab_model as g  # noqa: E402

p = g.misconfigured_project()
print("== Attacks as a Developer (dave) ==")
p.push_ci_file("dave", "feature-x", "script: [env]")
print("own branch, leaked vars:   ", sorted(p.run_pipeline_as("dave", "feature-x")))
print("push to main allowed:      ", p.can_push("dave", "main"))
print("trigger token on main:     ", sorted(p.trigger_pipeline("dave", 0, "main")))
print("== Audit ==")
for f in g.audit(p):
    print(f"[{f.severity:6}] {f.id:20} {f.detail}")
g.harden(p)
print("== After harden() ==")
print("findings left:             ", len(g.audit(p)))
print("dev push to main allowed:  ", p.can_push("dave", "main"))
print("dev leaked vars on branch: ", sorted(p.run_pipeline_as("dave", "feature-y")))
print("dev trigger on main:       ", sorted(p.trigger_pipeline("dave", 0, "main")))
