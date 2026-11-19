import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import minigw as g  # noqa: E402

keys = {"mobile-app": g.new_fake_api_key(), "partner-acme": g.new_fake_api_key()}
cfg = g.load_config(HERE / "fixtures" / "kong-like.json", keys)


def brute(target, label):
    hits = []
    for n in range(7330, 7350):
        status, h, body = target("POST", "/login", {}, json.dumps({"pin": f"{n:04d}"}))
        hits.append(status)
        if status == 200:
            print(f"   {label}: PIN found ({n:04d}) after {len(hits)} tries")
            return
    print(f"   {label}: statuses {hits[:8]}... -> 429s stop the attack; Retry-After={h.get('Retry-After')}")


print("1. Brute force the 4-digit PIN login")
api = g.UpstreamAPI()
brute(api, "direct to upstream (no gateway)")
api2 = g.UpstreamAPI()
gw = g.Gateway(cfg, {"orders-api": api2})
brute(lambda m, p, h, b: gw.handle(m, p, h, b), "through the gateway")
print(f"   upstream saw {api2.calls} login calls")

print("\n2. API key auth and per-key rate limits on /orders")
print("   no key      :", gw.handle("GET", "/orders")[0])
print("   unknown key :", gw.handle("GET", "/orders", {"apikey": g.new_fake_api_key()})[0])
statuses = [gw.handle("GET", "/orders", {"apikey": keys["mobile-app"]})[0] for _ in range(12)]
print("   mobile-app x12   :", statuses)
print("   partner-acme x1  :", gw.handle("GET", "/orders", {"apikey": keys["partner-acme"]})[0], "(own bucket, unaffected)")
gw.clock.advance(3)
print("   mobile-app after 3s:", [gw.handle("GET", "/orders", {"apikey": keys["mobile-app"]})[0] for _ in range(4)])

print("\n3. Security headers added at the edge")
status, h, body = gw.handle("GET", "/orders", {"apikey": keys["partner-acme"], "Origin": "https://shop.example"})
for k in sorted(h):
    print(f"   {k}: {h[k]}")
print("   upstream sent Server/X-Powered-By; gateway removed them:", "Server" not in h and "X-Powered-By" not in h)
