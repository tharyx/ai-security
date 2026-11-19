import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import userenum as u  # noqa: E402

USERS = {"alice": "pw-alice", "bob": "pw-bob"}
CANDIDATES = ["alice", "carol", "bob", "dave"]

print("=== VULNERABLE API (responses differ) ===")
vuln = u.VulnerableAuth(USERS)
for name in CANDIDATES:
    r = vuln.login(name, "wrong-password")
    print(f"  {name:6} -> {r.status}  {r.message!r:35} work={r.work_units}")
print("  enumerated users:", u.enumerate_users(vuln, CANDIDATES))

print("\n=== SECURE API (uniform response) ===")
sec = u.SecureAuth(USERS)
for name in CANDIDATES:
    r = sec.login(name, "wrong-password")
    print(f"  {name:6} -> {r.status}  {r.message!r:55} work={r.work_units}")
print("  enumerated users:", u.enumerate_users(sec, CANDIDATES))
