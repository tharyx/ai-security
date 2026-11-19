"""Demo: analyze pipelines and simulate artifact-store tampering."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyzer  # noqa: E402

doc = analyzer.load(HERE / "fixtures" / "pipelines.json")
for f in analyzer.analyze(doc):
    print(f"[{f.severity:8}] {f.rule:25} {f.pipeline:14} {f.detail[:70]}")
print()
by = {p["name"]: p for p in doc["pipelines"]}
for name, who in (("web-release", "contractor-role"), ("data-jobs", "allAuthenticatedUsers"), ("hardened", "contractor-role")):
    r = analyzer.run_pipeline(by[name], attacker=who)
    print(f"{name:12} attacker={who:22} tampered={r['tampered']!s:5} -> {r['result']}; payload={r['deployed']}")
