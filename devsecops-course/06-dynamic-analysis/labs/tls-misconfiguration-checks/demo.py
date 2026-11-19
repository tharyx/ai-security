import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

t = load_lab_module(__file__, "tlscheck")
today = date(2026, 11, 19)  # fixed date so the output is reproducible
for name in ("bad_server.json", "good_server.json"):
    cfg = json.loads((Path(__file__).parent / "fixtures" / name).read_text())
    found = t.analyze(cfg, today)
    print(f"== {cfg['host']}  grade {t.grade(found)}  ({len(found)} finding(s)) ==")
    for f in found:
        print(f"  [{f.severity:8}] {f.rule:24} {f.detail}")
