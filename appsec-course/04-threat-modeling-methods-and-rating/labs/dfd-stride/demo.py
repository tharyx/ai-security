"""Validate a DFD, then generate STRIDE-per-element threats and a Mermaid diagram."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import dfd  # noqa: E402

broken = dfd.load(HERE / "fixtures" / "broken_dfd.json")
print("=== Validating broken_dfd.json ===")
for e in dfd.validate(broken):
    print("  " + e)

model = dfd.load(HERE / "fixtures" / "password_reset_dfd.json")
print("\n=== password_reset_dfd.json ===")
print("validation errors:", dfd.validate(model) or "none")
print("boundary-crossing flows:", ", ".join(dfd.crossings(model)))
threats = dfd.stride_per_element(model)
print(f"STRIDE-per-element candidates: {len(threats)}")
for cat, n in dfd.summary(threats).items():
    print(f"  {cat:24} {n}")
print("\nFirst 8 candidates (target, letter, priority, question):")
for t in threats[:8]:
    print(f"  {t.target:11} {t.letter} {t.priority:8} {t.question}")
print("\n```mermaid")
print(dfd.mermaid(model))
print("```")
