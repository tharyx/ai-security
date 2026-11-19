import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import escape_analyzer as ea

for name in ("risky", "moderate", "hardened"):
    cfg = json.loads((Path(__file__).parent / "fixtures" / f"{name}.json").read_text())
    paths = ea.analyze(cfg, cfg.get("_setuid_files"))
    print(f"== {cfg['Name']} ({name}): verdict {ea.verdict(paths)}, {len(paths)} escape paths ==")
    for p in paths:
        print(f"  [{p.severity:<8}] {p.id:<18} {p.title}")
    if name == "risky":
        p = paths[0]
        print(f"\n  Explanation of the first one:\n    why: {p.why[:150]}...\n    fix: {p.fix}\n")
