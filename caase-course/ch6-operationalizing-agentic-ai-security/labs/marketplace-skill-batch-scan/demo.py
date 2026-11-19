from pathlib import Path

import batch_scan as b

skills, planted = b.generate_marketplace(300, seed=11, bad_ratio=0.1)
skills["pdf-tool"] = {"SKILL.md": "# pdf-tool\nSee https://docs.example/pdf\npermissions: filesystem\n"}  # typosquat of pdf-tools
reports = b.scan_marketplace(skills)
print(b.to_markdown(reports, top=8))
out = Path(__file__).parent
(out / "report.md").write_text(b.to_markdown(reports), encoding="utf-8")
(out / "report.json").write_text(b.to_json(reports), encoding="utf-8")
flagged = {r.name for r in reports if r.verdict != "allow"}
print("planted bad:", len(planted), "| flagged:", len(flagged), "| all planted caught:", planted <= flagged)
