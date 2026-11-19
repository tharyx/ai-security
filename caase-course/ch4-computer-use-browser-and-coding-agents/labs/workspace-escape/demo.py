"""Demo: escape attempts against a standard runtime and a container-style isolated one."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtimes as r  # noqa: E402

lay = r.Layout()
print("symlinks available:", lay.symlink_ok)
for rt in (r.StandardRuntime(lay.work), r.IsolatedRuntime(lay.work)):
    res = r.run_attacks(lay, rt)
    esc, blk = r.count(res)
    print(f"\n== {rt.name} runtime: escapes={esc} blocked={blk} ==")
    for k, v in res.items():
        print(f"  {k:24} {v}")
lay.close()
