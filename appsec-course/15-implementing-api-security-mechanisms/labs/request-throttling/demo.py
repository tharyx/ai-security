import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import throttle as t  # noqa: E402

print("1. Boundary burst: limit 10 per 60 s; attacker sends 10 at t=59.0-59.9 and 10 at t=60.0-60.9")
times = [59 + i / 10 for i in range(10)] + [60 + i / 10 for i in range(10)]
for name, lim in [("FixedWindow", t.FixedWindow(10, 60)), ("SlidingWindowLog", t.SlidingWindowLog(10, 60)),
                  ("SlidingWindowCounter", t.SlidingWindowCounter(10, 60)), ("TokenBucket", t.TokenBucket(10, 10 / 60))]:
    print(f"   {name:21} accepted {t.accepted_in(lim, times)} of 20 in under 2 seconds")

print("\n2. 429 with Retry-After")
lim = t.SlidingWindowLog(3, 60)
for i in range(4):
    ok, wait = lim.allow("key-A", 100 + i)
    print(f"   request {i + 1}: {t.http_response(ok, wait, 3)}")

print("\n3. Throttling: 2 req/s, max wait 2 s, 8 requests arrive at once")
th = t.Throttler(2, 2.0)
print("  ", [th.submit("client", 0.0) for _ in range(8)])

print("\n4. Limits at different stages")
edge = t.LayeredEdge()
scenarios = {
    "single-IP flood (100 req in 10 s)": [t.Request("198.51.100.9", "/products", "app-key") for _ in range(100)],
    "SQLi probe": [t.Request("198.51.100.20", "/search", "app-key", body="q=x' OR 1=1 --")],
    "password spray on one account from 40 IPs, 1/s": [t.Request(f"203.0.113.{i}", "/login", f"k{i}", account="cfo@corp.example") for i in range(40)],
}
now = 0.0
for label, reqs in scenarios.items():
    results = Counter()
    for r in reqs:
        results[edge.handle(r, now)[1]] += 1
        now += 0.1 if "flood" in label else 1.0
    print(f"   {label}: {dict(results)}")
edge2 = t.LayeredEdge()
burst = Counter(edge2.handle(t.Request(f"10.{i // 250}.{i % 250}.1", "/products", f"bot{i}"), 500.0)[1] for i in range(1000))
print(f"   botnet: 1000 IPs at the same instant: {dict(burst)}")
