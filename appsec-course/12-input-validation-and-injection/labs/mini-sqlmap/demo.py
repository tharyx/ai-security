import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mini_sqlmap as s  # noqa: E402

for secure in (False, True):
    t = s.Target(secure)
    print(f"== Target ({'parameterized' if secure else 'string-built SQL'}) GET /product?id=1 ==")
    r = s.detect(t)
    print("  [B] boolean-based blind:", "injectable" if r["boolean_blind"] else "not injectable")
    print("  [T] time-based blind   :", "injectable (5s virtual delay)" if r["time_based"] else "not injectable")
    if r["boolean_blind"]:
        value = s.extract(t, "SELECT value FROM secrets WHERE id=1")
        print(f"  dumped secrets.value = {value}  ({s.extract.requests} requests)")
    print()
