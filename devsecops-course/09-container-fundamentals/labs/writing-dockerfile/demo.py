import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bestpractice as bp

FIX = Path(__file__).parent / "fixtures"
CTX = {"app.py": 20, "requirements.txt": 2}
for name in ("bad", "good"):
    text = (FIX / f"{name}.Dockerfile").read_text()
    fs = bp.lint(text)
    print(f"== {name}.Dockerfile: {len(fs)} findings, score {bp.score(fs)} ==")
    for f in fs:
        print(f"  [{f.severity:<8}] {f.rule} line {f.line:>2}: {f.message[:84]}")
    cost = bp.rebuild_cost(text, CTX, "app.py")
    print(f"  edit app.py -> rebuilt {cost['rebuilt']} of {cost['layers']} layers ({cost['rebuilt_kb']} KB)\n")
