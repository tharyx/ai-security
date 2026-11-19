"""Demo: run the sample pipeline, then break it and watch the failure handling."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pipeline as p  # noqa: E402

text = (Path(__file__).parent / "sample.gitlab-ci.yml").read_text()


def show(title, res):
    print(f"\n== {title}: pipeline {res.status.upper()}")
    for r in res.jobs.values():
        rnd = f"round {r.round}" if r.round else "-"
        print(f"  {r.name:<12} {r.stage:<7} {r.status:<15} {rnd:<8} {r.reason}")
    print("  order:", " -> ".join(res.order))


show("on a feature branch", p.run_pipeline(text, {"CI_COMMIT_BRANCH": "feature-x"}))
show("on main", p.run_pipeline(text, {"CI_COMMIT_BRANCH": "main"}))
broken = text.replace("paths: [dist/app.bin]", "paths: [dist/other.bin]")
show("main, but compile forgot its artifact", p.run_pipeline(broken, {"CI_COMMIT_BRANCH": "main"}))
needs = text.replace("  script:\n    - require dist/app.bin\n    - echo deploying",
                     "  needs: [compile]\n  script:\n    - require dist/app.bin\n    - echo deploying")
show("deploy-prod with needs: [compile]", p.run_pipeline(needs, {"CI_COMMIT_BRANCH": "main"}))
