"""Demo: generate a CycloneDX-style SBOM for the fixture MCP server and analyze it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sbom as s  # noqa: E402

HERE = Path(__file__).resolve().parent
bom = s.generate_sbom(HERE / "fixtures" / "notes-mcp")
print("valid:", s.validate_sbom(bom) or "ok")
print("serialNumber:", bom["serialNumber"], "| specVersion:", bom["specVersion"])
print("top component:", bom["metadata"]["component"]["bom-ref"], [p["value"] for p in bom["metadata"]["component"]["properties"]])
print("first component:", json.dumps(bom["components"][0], indent=1)[:420], "...")
print()
report = s.analyze_sbom(bom, json.loads((HERE / "fixtures" / "advisories.json").read_text()), json.loads((HERE / "fixtures" / "policy.json").read_text()))
print(s.render_report(report))
(HERE / "notes-mcp.cdx.json").write_text(json.dumps(bom, indent=2), encoding="utf-8")
print("\nwrote notes-mcp.cdx.json (", len(json.dumps(bom)), "bytes )")
