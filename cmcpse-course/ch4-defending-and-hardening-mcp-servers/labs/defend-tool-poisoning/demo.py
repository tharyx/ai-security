"""Demo: scan and gate a catalogue that contains poisoned tool definitions (synthetic, harmless text)."""

from aisec_lab import load_lab_module

pd = load_lab_module(__file__, "poison_defense")
tools = list(pd.fixtures().values())
allowed, report = pd.ToolGate(reviewed={"add": "Add two integers and return the sum."}).filter(tools)

for v in report:
    detail = "; ".join(f"{f.rule}@{f.where}" for f in v.findings[:3])
    print(f"{v.action.upper():<6} {v.tool:<16} {detail}")
print("\nthe model receives:", [t["name"] for t in allowed])
