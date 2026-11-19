"""Demo: STRIDE per element and per crossing on the sample MCP architecture."""

from pathlib import Path

from aisec_lab import load_lab_module

sm = load_lab_module(__file__, "stride_mcp")
HERE = Path(__file__).resolve().parent

arch = sm.load_arch(HERE / "mcp_architecture.yaml")
print("DFD problems:", sm.validate(arch) or "none")
print("Flows that cross a trust boundary:", ", ".join(sorted(sm.crossings(arch), key=lambda x: int(x[1:]))))
findings = sm.find_threats(arch)
s = sm.summary(findings)
print(f"\n{s['total']} findings: {s['open']} open, {s['mitigated']} mitigated")
print("By STRIDE:", ", ".join(f"{k}={v}" for k, v in s["by_stride"].items()))

print("\nThe host element alone:")
for f in findings:
    if f.element_id == "host":
        print(f"  {f.id} [{f.stride}] {f.title}  ({', '.join(f.owasp_mcp) or '-'}) {f.status}")

print("\nOpen findings on boundary-crossing flows:")
for f in findings:
    if f.kind == "data_flow" and f.crossing and f.status == "open":
        print(f"  {f.id} {f.element_id} [{f.stride}] {f.title}")
