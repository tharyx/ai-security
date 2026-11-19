import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import detectors as d  # noqa: E402

src = (HERE / "fixtures" / "cases.py").read_text(encoding="utf-8")
truth = d.ground_truth(src)
print(f"{len(truth)} cases: {sum(v == 'vuln' for v in truth.values())} vulnerable, {sum(v == 'safe' for v in truth.values())} safe\n")

flagged = {name: {h.function for h in fn(src)} for name, fn in d.DETECTORS.items()}
print(f"{'case':36} {'truth':6} regex  ast    graph")
for case, t in truth.items():
    row = "  ".join(f"{'FLAG' if case in flagged[n] else '-':5}" for n in d.DETECTORS)
    mark = ""
    for n in d.DETECTORS:
        if (case in flagged[n]) != (t == "vuln"):
            mark += f" <{n}:{'FP' if t == 'safe' else 'FN'}>"
    print(f"{case:36} {t:6} {row}{mark}")

print()
for name in d.DETECTORS:
    s = d.score(src, name)
    print(f"{name:6} precision={s['precision']:<5} recall={s['recall']:<5} FP={s['fp']} FN={s['fn']}")

print("\n== taint path found by the graph detector for case_g_helper_function")
for h in d.detect_graph(src):
    if h.function == "case_g_helper_function":
        print(h.why)
