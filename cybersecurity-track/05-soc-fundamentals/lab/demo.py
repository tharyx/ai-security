"""Demo: triage the whole synthetic queue and print a table, then one full case note.

Run:  python cybersecurity-track/05-soc-fundamentals/lab/demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage  # noqa: E402  (demo.py may import siblings)


def main() -> None:
    results = triage.triage_default()
    print(f"{'ID':7} {'RULE':22} {'SCORE':>5}  {'VERDICT':21} {'ACTION':30} ATT&CK")
    print("-" * 110)
    for t in results:
        ids = ",".join(tid for _, tid, _ in t.attack)
        print(f"{t.id:7} {t.alert['rule']:22} {t.score:>5}  {t.verdict:21} {t.escalation:30} {ids}")
    counts = {}
    for t in results:
        counts[t.verdict] = counts.get(t.verdict, 0) + 1
    print("\nSummary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("\n" + "=" * 70)
    for wanted in ("A-1006", "A-1005"):
        print(next(t for t in results if t.id == wanted).notes)
        print("=" * 70)


if __name__ == "__main__":
    main()
