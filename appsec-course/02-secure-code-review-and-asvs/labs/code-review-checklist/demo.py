import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reviewer  # noqa: E402

for name in ("vulnerable", "fixed"):
    fs = reviewer.review_tree(HERE / "fixtures" / name)
    print(reviewer.report(fs, f"Secure code review: fixtures/{name}"))
    print(f"\nfindings: {len(fs)}, gate exit code: {reviewer.gate(fs)}\n")
