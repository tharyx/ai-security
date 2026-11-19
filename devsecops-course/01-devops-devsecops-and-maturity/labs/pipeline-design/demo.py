"""Demo: validate the good design, break it, then simulate blue/green releases."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pipeline as p  # noqa: E402

spec = p.load(str(Path(__file__).parent / "pipeline.yaml"))
print("== validate pipeline.yaml")
print("  issues:", [(i.severity, i.rule) for i in p.validate(spec)] or "none")

bad = p.load(str(Path(__file__).parent / "pipeline.yaml"))
bad["stages"] = [s for s in bad["stages"] if s["type"] != "dast"]
bad["stages"][1]["allow_failure"] = True
bad["stages"][-1].pop("rollback")
print("== validate a broken copy (no DAST, SCA may fail, no rollback)")
for i in p.validate(bad):
    print(f"  {i.severity:<8} {i.rule:<14} {i.message}")

print("\n== blue/green: good release")
bg = p.BlueGreen("blue", "1.0.0")
for line in bg.release("1.1.0").events:
    print("  ", line)

print("\n== blue/green: health check never passes")
bg = p.BlueGreen("blue", "1.0.0")
r = bg.release("1.1.0", health=lambda env, ver: False)
for line in r.events:
    print("  ", line)
print("  status:", r.status, "| live:", r.live)

print("\n== blue/green: healthy, but errors after the flip")
bg = p.BlueGreen("blue", "1.0.0")
r = bg.release("1.1.0", post_flip=lambda ver: False)
for line in r.events:
    print("  ", line)
print("  status:", r.status, "| live:", r.live)

print("\n== canary: 5% 25% 50% 100%, errors jump at 50%")
res = p.canary_rollout([5, 25, 50, 100], lambda pct: 0.002 if pct < 50 else 0.05)
print("  ", res)
