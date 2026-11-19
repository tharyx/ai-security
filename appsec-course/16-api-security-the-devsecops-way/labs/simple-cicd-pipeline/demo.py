import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pipeline as p  # noqa: E402

defn = p.load(HERE / "fixtures/pipeline.json")

print("1. main branch, no approval yet")
print(p.run(defn, branch="main").summary())

print("\n2. main branch, deploy-prod approved")
r = p.run(defn, branch="main", approvals={"deploy-prod"})
print(r.summary())
print("   build artifact digest:", r.jobs["build"].artifacts)
print("   deploy log:", r.jobs["deploy-prod"].log)

print("\n3. feature branch with a failing unit test")
print(p.run(defn, branch="feature/bola-fix", extra_vars={"SIMULATE_TEST_FAILURE": "1"}).summary())

print("\n4. invalid definitions are rejected before anything runs")
bad = {"stages": ["build", "deploy"], "jobs": {
    "deploy": {"stage": "deploy", "script": ["deploy"], "needs": ["build"]},
    "build": {"stage": "build", "script": ["compile", "curl-bash"], "needs": ["deploy"]}}}
for e in p.validate(bad):
    print("   -", e)
