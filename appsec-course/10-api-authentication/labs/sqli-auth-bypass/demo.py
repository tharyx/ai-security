import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sqli_login as s  # noqa: E402

con = s.make_db()
print("=== Vulnerable login (string-concatenated SQL) ===")
print("  valid alice/pw-alice     ->", s.login_vulnerable(con, "alice", "pw-alice"))
print("  wrong password           ->", s.login_vulnerable(con, "alice", "nope"))
print(f"  payload {s.BYPASS_USERNAME!r} ->", s.login_vulnerable(con, s.BYPASS_USERNAME, "x"))
print(f"  payload {s.BYPASS_ADMIN!r}       ->", s.login_vulnerable(con, s.BYPASS_ADMIN, "x"))

print("\n=== Secure login (bound parameters) ===")
print("  valid alice/pw-alice     ->", s.login_secure(con, "alice", "pw-alice"))
print(f"  payload {s.BYPASS_USERNAME!r} ->", s.login_secure(con, s.BYPASS_USERNAME, "x"))
print(f"  payload {s.BYPASS_ADMIN!r}       ->", s.login_secure(con, s.BYPASS_ADMIN, "x"))
