import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repo  # noqa: E402

db = repo.make_db()
UNION = "zz' UNION SELECT username, password_hash FROM users--"

print("1. search, UNION payload")
print("   vuln :", [r[0] for r in repo.search_vuln(db, UNION)])
print("   fixed:", repo.search_fixed(db, UNION))
print("   fixed, normal input 'jam':", repo.search_fixed(db, "jam"))

print("\n2. login as admin'-- with a wrong password")
print("   vuln :", repo.login_vuln(db, "admin'--", "wrong"))
print("   fixed:", repo.login_fixed(db, "admin'--", "wrong"))
print("   fixed, right password:", repo.login_fixed(db, "alice", "alice-lab-pw"))

print("\n3. ORDER BY used as a yes/no oracle (is admin's hash first char < '8'?)")
cond_true = "1=1"
probe = "(SELECT substr(password_hash,1,1) FROM users WHERE username='admin') < '8'"
print("   vuln, condition 1=1   :", repo.order_by_oracle(repo.list_sorted_vuln, db, cond_true))
print("   vuln, condition 1=0   :", repo.order_by_oracle(repo.list_sorted_vuln, db, "1=0"))
print("   vuln, probe hash char :", repo.order_by_oracle(repo.list_sorted_vuln, db, probe))
try:
    repo.order_by_oracle(repo.list_sorted_fixed, db, probe)
except ValueError as e:
    print("   fixed:", e)
print("   fixed, sort=-price    :", repo.list_sorted_fixed(db, "-price"))

print("\n4. IN list with '1) OR (1=1'")
print("   vuln :", repo.by_ids_vuln(db, "1) OR (1=1"))
try:
    repo.by_ids_fixed(db, "1) OR (1=1")
except ValueError as e:
    print("   fixed: rejected:", e)
print("   fixed, '1,3':", repo.by_ids_fixed(db, "1,3"))
