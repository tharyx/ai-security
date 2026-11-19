"""Demo: promote a build through dev, staging, prod with approval; fail a release; roll back."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cd  # noqa: E402

s = cd.DeploymentSystem()
for v, content in (("1.0", "build-one"), ("1.1", "build-two")):
    print(f"CI built {v}: {s.register_artifact(v, content)[:23]}...")

for v in ("1.0", "1.1"):
    s.deploy("dev", v, "ci")
    s.deploy("staging", v, "ci")
    if v == "1.0":
        try:
            s.deploy("prod", v, "alice")
        except cd.DeployError as e:
            print("prod without approval  :", e)
        s.request_approval("prod", v, "alice")
        try:
            s.approve("prod", v, "alice")
        except cd.DeployError as e:
            print("self-approval          :", e)
        s.approve("prod", v, "release-manager")
        print("prod 1.0               :", s.deploy("prod", v, "alice"))
    else:
        s.request_approval("prod", v, "alice")
        s.approve("prod", v, "security-lead")
        print("prod 1.1 (unhealthy)   :", s.deploy("prod", v, "alice", healthy=lambda r: False))

print("state after auto-rollback:", s.state())
print("\naudit trail:")
for a in s.audit:
    extra = {k: v for k, v in a.items() if k not in ("t", "event", "digest")}
    print(" ", a["event"].ljust(20), extra)
