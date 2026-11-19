"""Demo: threat-model the multi-agent support platform."""
from aisec_lab import load_lab_module

tm = load_lab_module(__file__, "threat_model")
arch, lib = tm.load()
print("DFD problems:", tm.validate(arch) or "none")
print("Boundary crossings (flow -> trust change):", tm.crossings(arch))
findings = tm.find_threats(arch, lib)
print("Summary:", tm.summary(findings))
print("\nTop 8 by agentic risk score")
print(tm.to_markdown(findings, 8))
