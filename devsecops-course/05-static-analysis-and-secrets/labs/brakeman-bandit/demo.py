import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import brakeman_bandit as bb  # noqa: E402

FIX = HERE / "fixtures"
rb, ignored = bb.from_brakeman(FIX / "brakeman.json")
py = bb.from_bandit_like(FIX / "pyapp")
print(f"brakeman: {len(rb)} warnings ({len(ignored)} already ignored in the report); bandit-like: {len(py)} issues")

all_f = bb.merge(rb, py)
print("\n== one list, worst first (score = severity x confidence)")
for f in all_f:
    cwe = f"CWE-{f.cwe}" if f.cwe else "no CWE"
    print(f"score {f.score}  {f.severity:6}/{f.confidence:6} {f.tool:11} {f.rule:18} {cwe:8} {f.path}:{f.line}  {f.title}")

print("\n== grouped by CWE across both languages")
for cwe, items in sorted(bb.by_cwe(all_f).items(), key=lambda kv: str(kv[0])):
    print(f"CWE-{cwe}: " + ", ".join(f"{i.tool}:{i.path}" for i in items))

print("\n== gates")
print("fail on score >= 6          -> exit", bb.gate(all_f, 6))
base = {f.fingerprint for f in all_f if f.score >= 6}
print("same gate with all current findings baselined -> exit", bb.gate(all_f, 6, base))
