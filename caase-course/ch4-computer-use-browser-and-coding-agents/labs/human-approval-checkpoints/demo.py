"""Demo: classification, exact-action display, hash binding, timeout-means-deny."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import approval as a  # noqa: E402

clock = [100.0]
gate = a.ApprovalGate(clock=lambda: clock[0], decision_timeout=60)
ran = []

for act in ({"type": "shell", "command": "rm -rf ./build"}, {"type": "git", "args": ["status"]},
            {"type": "payment", "amount": 25, "payee": "Shop"}, {"type": "mystery"}):
    print(a.classify(act)["risk"].ljust(15), a.canonical(act))

act = {"type": "git", "args": ["push", "--force", "origin", "main"]}
print("\nwhat the human sees:\n" + a.render(act))
req = gate.request(act)
gate.decide(req.id, True, "alice")
print("\nswapped action :", a.execute({"type": "git", "args": ["push", "--force", "origin", "release"]}, gate, ran.append, req.id))
print("exact action   :", a.execute(act, gate, ran.append, req.id))
print("replay         :", a.execute(act, gate, ran.append, req.id))

req2 = gate.request({"type": "delete", "path": "notes.txt"})
clock[0] += 61
print("after timeout  :", a.execute({"type": "delete", "path": "notes.txt"}, gate, ran.append, req2.id))
print("\nactions actually run:", len(ran))
