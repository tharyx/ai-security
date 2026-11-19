import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluate  # noqa: E402

bl, cc = evaluate.bl, evaluate.cc
APP = HERE / "fixtures" / "enterprise_app"

print("== 1. built-in checks (Bandit-like) on legacy.py")
for i in bl.scan_path(APP / "legacy.py", [f for f in bl.load_checks(bl) if f._test_id != "B608"]):
    print(f"{i.test_id} {i.severity:6}/{i.confidence:6} CWE-{i.cwe:<3} line {i.lineno:<3} {i.text}")

print("\n== 2. our four custom checks on the enterprise app")
custom = evaluate.custom_issues(APP)
for i in custom:
    print(f"{i.test_id} {i.severity:6}/{i.confidence:6} CWE-{i.cwe:<3} {i.filename}:{i.lineno:<3} {i.text}")

print("\n== 3. false positives: generic rules vs custom rules (function-level scoring)")
base = evaluate.baseline_issues(APP)
for label, issues in (("baseline (built-in B608 + grep for secret words)", base), ("custom checks", custom)):
    sc = evaluate.score(APP, issues)
    print(label)
    for cat, s in sc.items():
        print(f"  {cat:11} TP={s['tp']} FP={s['fp']} FN={s['fn']}  precision={s['precision']}  recall={s['recall']}")
    print("  total", evaluate.summarize(sc))
