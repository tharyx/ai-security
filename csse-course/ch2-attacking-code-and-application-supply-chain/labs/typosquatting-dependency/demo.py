import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import detector  # noqa: E402

pop = json.loads((HERE / "fixtures" / "popular.json").read_text())
text = (HERE / "fixtures" / "requirements.txt").read_text()
for f in detector.scan_requirements(text, pop):
    print(f"{f.package:18} {f.kind:11} -> {f.target:12} {f.detail}")
