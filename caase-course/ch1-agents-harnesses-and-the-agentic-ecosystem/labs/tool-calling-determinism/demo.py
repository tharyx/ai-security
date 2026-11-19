"""Run two mock local models concurrently, 40 runs per task, in three pipelines.

    .venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/tool-calling-determinism/demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import toolcalls as tc  # noqa: E402

models = [tc.SteadyModel(), tc.FlakyModel()]
for mode in ("raw", "retry", "constrained"):
    rep = tc.summarize(tc.run_all(models, tc.TASKS, 40, mode, concurrent=True))
    print(f"\n[{mode}]  (3 tasks x 40 runs per model, run in threads)")
    print(f"{'model':<11}{'parse':>8}{'schema':>8}{'correct':>9}{'consistent':>12}{'attempts':>10}")
    for name, r in rep.items():
        print(f"{name:<11}{r['parse_valid']:>8.2f}{r['schema_valid']:>8.2f}{r['correct']:>9.2f}"
              f"{r['consistency']:>12.2f}{r['avg_attempts']:>10.2f}")
