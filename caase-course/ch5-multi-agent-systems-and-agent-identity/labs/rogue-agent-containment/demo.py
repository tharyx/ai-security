import tempfile
from pathlib import Path

from failsafe import SafetyController
from rogue_agent import Denied, Monitor, Runtime, terminate

rt = Runtime()
rt.store.data["config"] = "original"
bad = rt.spawn("bad", {"read", "write"})
rt.act(bad, "write", "config", "TAMPERED")
for _ in range(4):
    try:
        rt.act(bad, "shell", "rm")
    except Denied:
        pass
bad.queue += ["task-1", "task-2"]
print("monitor findings:", [(f.rule, f.detail) for f in Monitor().scan(rt, bad)])
print("config before termination:", rt.store.data["config"])
with tempfile.TemporaryDirectory() as d:
    rep = terminate(rt, bad, Path(d), "tool probing + config tamper")
    print("steps:", " -> ".join(rep.steps))
    print(f"dead-lettered={rep.dead_lettered} revoked={rep.credentials_revoked} rolled_back={rep.rolled_back}")
    print("evidence sha256:", rep.evidence_sha256[:16], "...")
print("config after termination:", rt.store.data["config"])

print("\nPhysical-world fail-safe (simulated valve)")
c = SafetyController()
c.heartbeat(0)
print("set_flow 20 ->", c.propose("set_flow", 20, 1), c.state)
print("set_flow 500 ->", c.propose("set_flow", 500, 2))
c.tick(30)
print("after 29s without heartbeat:", c.state, "| tripped:", c.tripped)
