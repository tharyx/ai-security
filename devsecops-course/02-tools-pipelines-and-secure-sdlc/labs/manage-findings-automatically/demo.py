"""Demo: three tool outputs in, one findings list, a gate decision and new tickets out."""

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import findings as f  # noqa: E402

fx = Path(__file__).parent / "fixtures"
today = date(2026, 11, 19)  # fixed so the output is reproducible
policy = f.load_policy(fx / "policy.yaml")
res = f.process(f.load_json(fx / "semgrep.sarif"), f.load_json(fx / "zap-report.json"),
                f.load_json(fx / "npm-audit.json"), policy, f.load_json(fx / "existing-tickets.json"), today)

print(f"raw findings from 3 tools: {res['raw_count']}  ->  after dedup and waivers: {len(res['findings'])}")
print(f"{'sev':<9}{'kind':<6}{'rule':<16}{'x':<3}{'location':<22}title")
for x in res["findings"]:
    print(f"{x['severity']:<9}{x['kind']:<6}{x['rule']:<16}{x['occurrences']:<3}{x['location']:<22}{x['title'][:50]}")
print("\nwaived:", [(w['rule'], w['waiver'][:30]) for w in res["waived"]])
print("expired waivers (no longer hide anything):", [w["rule"] for w in res["expired_waivers"]])
print("\ngate:", "PASS" if res["gate"]["passed"] else "FAIL", res["gate"]["counts"])
print("breaches (found, allowed):", res["gate"]["breaches"])
t = res["tickets"]
print(f"\ntickets: {len(t['created'])} new, {len(t['already_tracked'])} already tracked, close candidates: {t['to_close']}")
print(json.dumps(t["created"][0], indent=2))
