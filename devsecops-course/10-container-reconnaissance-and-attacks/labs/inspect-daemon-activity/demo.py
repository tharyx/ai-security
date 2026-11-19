import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import events as ev

FIX = Path(__file__).parent / "fixtures"
events = ev.parse((FIX / "events.jsonl").read_text().splitlines())
print("Timeline:")
for line in ev.timeline(events):
    print("  " + line)
print("\nAlerts:")
for a in ev.detect(events):
    print(f"  [{a['severity']:<8}] {a['rule']:<14} {a['time']}  {a['message'][:95]}")
print("\nLog findings:")
for f in ev.scan_logs((FIX / "app.log").read_text().splitlines()):
    print("  " + f)
