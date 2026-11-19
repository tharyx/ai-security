import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import metrics_alerts as m  # noqa: E402

prev, cur = m.load(HERE / "fixtures/scrape_t0.prom"), m.load(HERE / "fixtures/scrape_t1.prom")
print("Dashboard (last 60 s):")
print(m.dashboard(prev, cur))
print("\nAlerts:")
for a in m.evaluate(prev, cur):
    print(f"  [{a.severity:8}] {a.rule:18} {a.container:12} {a.detail}")
