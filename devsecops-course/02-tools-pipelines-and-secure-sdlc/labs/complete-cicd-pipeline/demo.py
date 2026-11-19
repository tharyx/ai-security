"""Demo: a vulnerable commit is stopped, the fixed commit goes through to deploy."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r  # noqa: E402

pipe, adv = r.load_pipeline(), r.load_advisories()


def show(title, run):
    print(f"\n== {title}: pipeline {run.status.upper()}")
    for j in run.jobs:
        print(f"  {j.stage:<7} {j.name:<16} {j.status:<9} {j.reason}")
        for f in j.findings:
            print(f"            - [{f['severity']}] {f['rule']}: {f['title']} @ {f['where']}")


app = r.load_app()
show("commit 1 (lodash 4.17.15 in package.json)", r.run_pipeline(pipe, app, adv))

app["package.json"] = app["package.json"].replace("4.17.15", "4.17.21")
show("commit 2 (dependency bumped)", r.run_pipeline(pipe, app, adv))
good = dict(app)

app["server.js"] += '\nconst q = "SELECT * FROM users WHERE id = " + req.query.id;\n'
show("commit 3 (someone adds SQL concatenation)", r.run_pipeline(pipe, app, adv))

show("commit 2 again, but on a feature branch", r.run_pipeline(pipe, good, adv, branch="feature-x"))
