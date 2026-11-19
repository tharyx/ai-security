import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mass_assign as m  # noqa: E402

attack = json.dumps({"display_name": "Alice", "is_admin": True, "credit": 100000, "email_verified": True})
print("PATCH /users/1 body:", attack)
print("vulnerable ->", m.update_profile_vuln(m.Store(), 1, attack))
print("secure     ->", m.update_profile_safe(m.Store(), 1, attack))
print("secure, legit change ->", m.update_profile_safe(m.Store(), 1, json.dumps({"display_name": "Alice K"})))
