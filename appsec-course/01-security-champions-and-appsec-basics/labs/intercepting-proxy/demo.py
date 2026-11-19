"""Walk through a Burp-style session against the vulnerable and the secure checkout."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import miniproxy  # noqa: E402
import target_app  # noqa: E402

CHECKOUT = ("POST /checkout HTTP/1.1\r\nHost: shop.example\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\nsku=7&price=499.00&qty=1")
ADMIN = "GET /admin HTTP/1.1\r\nHost: shop.example\r\nCookie: role=customer\r\n\r\n"
COUPON = ("POST /coupon HTTP/1.1\r\nHost: shop.example\r\n"
          "Content-Type: application/x-www-form-urlencoded\r\n\r\ncode=§X§")
GUESSES = ["AAAA", "SPRING10", "WELCOME41", "VIP", "FREESHIP", "WELCOME43", "WELCOME42"]


def tamper_price(req):
    req.body = req.body.replace("price=499.00", "price=0.01")
    return req


for label, cls in (("VULNERABLE", target_app.VulnerableCheckout), ("SECURE", target_app.SecureCheckout)):
    print(f"===== {label} =====")
    proxy = miniproxy.InterceptingProxy(cls())

    print("-- 1. Raw request/response as the Proxy tab shows it")
    print(proxy.send("GET /product/7 HTTP/1.1\r\nHost: shop.example\r\n\r\n").replace("\r\n", "\n"))

    print("\n-- 2. Intercept and change the hidden price field")
    proxy.on_request(tamper_price)
    raw = proxy.send(CHECKOUT)
    print("forwarded body:", proxy.history[-1][0].body)
    print("response:", raw.split("\r\n")[0], "|", miniproxy.parse_response(raw).body)
    proxy.request_hooks.clear()

    print("\n-- 3. Match-and-replace rule: role=customer -> role=admin")
    proxy.add_match_replace(r"role=customer", "role=admin")
    resp = miniproxy.parse_response(proxy.send(ADMIN))
    print("GET /admin ->", resp.status, resp.reason, "|", resp.body)
    proxy.match_replace.clear()

    print("\n-- 4. Repeater: resend history item 0 as POST")
    r = proxy.repeater(0, lambda q: setattr(q, "method", "POST"))
    print("repeated ->", r.status, r.reason, "| class:", miniproxy.status_class(r.status))

    print("\n-- 5. Intruder (Sniper) on the coupon code")
    for payload, status, length in proxy.intruder_sniper(COUPON, GUESSES):
        print(f"   {payload:10} status={status} length={length}")
    print("history size:", len(proxy.history))
    print()
