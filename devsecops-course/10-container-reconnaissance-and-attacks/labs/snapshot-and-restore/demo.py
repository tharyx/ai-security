import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import snapshots as sn

base = sn.Image("web:1.0", [{"/app/app.py": "v1", "/etc/motd": "hello", "/bin/sh": "sh"}], {"env": ["MODE=prod"], "cmd": ["python", "app.py"]}, ["FROM scratch", "COPY app"])
c = sn.Container(base, "suspicious")
t1 = dict(c.fs)
c.write("/tmp/dropper.sh", "canary-payload")
c.write("/app/app.py", "v1-tampered")
c.delete("/etc/motd")
print("docker diff:", c.diff())
t2 = dict(c.fs)
print("snapshot T1 vs T2:", sn.snapshot_diff(t1, t2))

img = c.commit("evidence:1")
print("\ncommit ->", img.name, "| layers:", len(img.layers), "| history:", img.history[-1])
r = sn.restore(img, "analysis-copy")
print("restored copy has dropper:", "/tmp/dropper.sh" in r.fs, "| and the deleted motd:", "/etc/motd" in r.fs)
print("original image still clean :", "/tmp/dropper.sh" not in base.rootfs())
print("\nMethod comparison:")
for m, v in sn.compare_methods(c).items():
    print(f"  {m:<7} history={v['keeps_history']!s:<5} config={v['keeps_config']!s:<5} layers={v['keeps_layers']!s:<5} -> {v['result']}")
