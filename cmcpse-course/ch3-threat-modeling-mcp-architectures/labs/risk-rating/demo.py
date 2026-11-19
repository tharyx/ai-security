"""Demo: rate the STRIDE findings, rank them and print the executive summary."""

from aisec_lab import load_lab_module

rr = load_lab_module(__file__, "rate_risks")
sm = rr.sm

arch = sm.load_arch()
rows = rr.build_register(arch, sm.find_threats(arch))
print("Inherent:", rr.severity_counts(rows, "inherent"))
print("Residual:", rr.severity_counts(rows))
print("\nTop 8 of the register:")
for i, r in enumerate(rows[:8], 1):
    print(f"{i}. {r['finding']} {r['residual']:<8} {r['element']}: {r['threat']}")
print()
print(rr.exec_summary(arch, rows))
