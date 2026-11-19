"""Threat-model the weak and the hardened design and compare them.

    .venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/atlas-threat-model-agent/demo.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import threatmodel as tm  # noqa: E402

weak, hard = tm.load(HERE / "system.yaml"), tm.load(HERE / "system-hardened.yaml")
print(tm.report(weak))
print()
for label, sysd in (("weak", weak), ("hardened", hard)):
    s = tm.summary(tm.analyze(sysd))
    print(f"{label:<9} findings={s['findings']:>2} total_score={s['total_score']:>3} max={s['max_score']:>2} "
          f"critical/high={s['critical_or_high']:>2} ASI hit={len(s['asi_hit'])}/10 tactics hit={len(s['tactics_hit'])}/14")
