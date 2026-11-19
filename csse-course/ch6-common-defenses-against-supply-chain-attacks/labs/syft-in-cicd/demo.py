"""Demo: run the pipeline on main and on a feature branch."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pipeline_runner as p  # noqa: E402

for branch in ("main", "feature-x"):
    r = p.run(p.PIPELINE, p.WORKSPACE, {"CI_COMMIT_BRANCH": branch})
    print(f"branch {branch}: jobs={r['jobs']} artifacts={list(r['artifacts'])}")
print("log (main):", p.run(p.PIPELINE, p.WORKSPACE, {"CI_COMMIT_BRANCH": "main"})["log"])
print("lint good pipeline:", p.lint_pipeline(p.PIPELINE))
bad = p.PIPELINE.replace("1.0.0", "latest").replace("    expire_in: 90 days\n", "")
print("lint weakened pipeline:", p.lint_pipeline(bad))
