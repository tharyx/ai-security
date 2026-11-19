"""Demo: risky RBAC subjects and a who-can query."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rbac_risk as r  # noqa: E402

roles, bindings = r.load()
seen = set()
for x in r.risky_subjects(roles, bindings):
    key = (x["subject"], x["why"])
    if key in seen:
        continue
    seen.add(key)
    print(f"[{x['severity']:8}] {x['subject']:34} via {x['binding']:16} {x['why']}")
print("who can get secrets:", r.who_can(roles, bindings, "get", "secrets"))
print("who can create pods/exec:", r.who_can(roles, bindings, "create", "pods/exec"))
