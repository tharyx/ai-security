"""Compare images and lint the Dockerfile examples. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/secure-mini-image/demo.py
"""
import importlib.util
import sys
from pathlib import Path

import compare as cp

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("lint06", HERE.parents[3] / "06-ai-devsecops/docker/lab/dockerfile_lint.py")
lint06 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lint06
spec.loader.exec_module(lint06)

print(f"{'image':30} {'MB':>5} {'pkgs':>5} {'C+H':>4} {'shell':>5} {'size':>5} {'score':>7}")
for r in cp.table(cp.load(HERE / "fixtures/images.json")):
    print(f"{r['name']:30} {r['size_mb']:5} {r['packages']:5} {r['crit+high']:4} {r['shell']:>5} {r['size_vs_full']:>5} {r['score']:7}")
print()
for name in ("Dockerfile.bloated", "Dockerfile.go-scratch", "Dockerfile.python-distroless"):
    findings = lint06.lint((HERE / "examples" / name).read_text())
    print(f"{name}: {len(findings)} finding(s) {sorted({f.rule_id for f in findings})}")
