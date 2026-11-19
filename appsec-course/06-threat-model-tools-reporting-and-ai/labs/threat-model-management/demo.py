import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import tm_manage as m  # noqa: E402

threats = m.load(HERE / "fixtures" / "threats.json")
TODAY = date(2026, 11, 19)
REPO = {"src/auth/mfa.py", "tests/test_mfa.py", "src/rate_limit.py"}  # ratelimit.py was renamed

print("== Naive export: run the model three times ==")
naive = []
for _ in range(3):
    naive = m.naive_sync(threats, naive)
print(f"  {len(naive)} tickets for {sum(t['status'] == 'open' for t in threats)} open threats (duplicates)")

print("\n== Managed sync: three runs ==")
tracker = {}
for run in range(1, 4):
    tracker, notes = m.sync(threats, tracker, TODAY)
    print(f"  run {run}: {len(tracker)} tickets; notes: {notes or 'none'}")

print("\n== Someone closes the BOLA ticket without fixing it ==")
bola = m.fingerprint(threats[0])
tracker[bola]["state"] = "Done"
tracker, notes = m.sync(threats, tracker, TODAY)
for n in notes:
    print("  ", n)

print("\n== Code links ==")
code = m.check_code_links(threats, REPO)
for p in code:
    print("  ", p)

print("\n== Generated documentation ==")
print(m.to_markdown("Shop", threats))

print("\nCI gate exit code:", m.ci_gate(threats, notes, code))
