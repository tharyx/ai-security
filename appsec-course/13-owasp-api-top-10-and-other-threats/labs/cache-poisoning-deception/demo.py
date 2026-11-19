import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cache_lab as c  # noqa: E402

for secure in (False, True):
    origin = c.Origin(secure)
    cache = c.Cache(origin, secure)
    print(f"===== {'SECURE' if secure else 'VULNERABLE'} cache + origin =====")
    print("1 attacker GET / with X-Forwarded-Host: evil.example ->", cache.get("/", {"X-Forwarded-Host": "evil.example"})[2:])
    print("  victim   GET / (no special headers)             ->", cache.get("/")[2:])
    status = cache.get("/account/nothing.css", {"Cookie": "FAKE-sess-victim"})
    print("2 victim clicks /account/nothing.css               ->", status[0], status[3])
    leak = cache.get("/account/nothing.css")
    print("  attacker GET /account/nothing.css (no cookie)   ->", leak[0], leak[2] or "(no body)", leak[3])
    print()

print("== Memcached exposure audit ==")
for cfg in ({"listen": "0.0.0.0", "udp_port": 11211, "internet_facing": True},
            {"listen": "10.0.4.12", "udp_port": 0, "sasl": True, "tls": True}):
    print(cfg, "->", c.audit_memcached(cfg) or "clean")
