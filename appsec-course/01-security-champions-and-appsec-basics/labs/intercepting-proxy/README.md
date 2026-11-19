# Lab: A mini intercepting proxy (Burp-style) and HTTP anatomy

**Course exercise:** Working with Burp Suite; also HTTP Requests, HTTP Responses and HTTP Status Codes. Lessons: [03 AppSec and HTTP basics](../../03-appsec-and-http-basics.md), [04 Tools of the trade and Burp](../../04-tools-of-the-trade-and-burp.md). Real tool: [real-tools/burp-suite.md](../../real-tools/burp-suite.md).

**Time:** 60 minutes. **Tests:** 12, all offline. **Safety:** the proxy never opens a socket; it calls an in-process app. Only test systems you own or have written permission to test.

## Goal

Learn the Burp workflow (intercept, history, match and replace, Repeater, Intruder) and the raw HTTP format by building and using a tiny proxy, then see why **client-side** controls fail and server-side ones hold.

## Concept

- [miniproxy.py](miniproxy.py): `parse_request` / `parse_response` turn raw HTTP text into objects and back (`to_raw()` always recomputes `Content-Length`); `InterceptingProxy` adds request/response hooks, match-and-replace rules, `history`, `repeater()` and `intruder_sniper()` (one `§position§`).
- [target_app.py](target_app.py): `VulnerableCheckout` trusts a hidden `price` field and a `role` cookie and allows unlimited coupon guesses; `SecureCheckout` looks up the price on the server, keeps the role in a server-side session and returns **429** after five coupon attempts.

## Run

```text
.venv/Scripts/python appsec-course/01-security-champions-and-appsec-basics/labs/intercepting-proxy/demo.py
.venv/Scripts/python -m pytest appsec-course/01-security-champions-and-appsec-basics/labs/intercepting-proxy -q -p no:cacheprovider
```

## Expected output (real run)

```text
===== VULNERABLE =====
-- 1. Raw request/response as the Proxy tab shows it
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 181

<h2>Noise-cancelling headphones</h2><form method=POST action=/checkout><input type=hidden name=sku value=7><input type=hidden name=price value=499.00><input name=qty value=1></form>

-- 2. Intercept and change the hidden price field
forwarded body: sku=7&price=0.01&qty=1
response: HTTP/1.1 200 OK | charged 0.01

-- 3. Match-and-replace rule: role=customer -> role=admin
GET /admin -> 200 OK | admin panel: 1,204 orders

-- 4. Repeater: resend history item 0 as POST
repeated -> 405 Method Not Allowed | class: 4xx Client error

-- 5. Intruder (Sniper) on the coupon code
   AAAA       status=200 length=7
   SPRING10   status=200 length=7
   WELCOME41  status=200 length=7
   VIP        status=200 length=7
   FREESHIP   status=200 length=7
   WELCOME43  status=200 length=7
   WELCOME42  status=200 length=39
history size: 11

===== SECURE =====
-- 1. Raw request/response as the Proxy tab shows it
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 181

<h2>Noise-cancelling headphones</h2><form method=POST action=/checkout><input type=hidden name=sku value=7><input type=hidden name=price value=499.00><input name=qty value=1></form>

-- 2. Intercept and change the hidden price field
forwarded body: sku=7&price=0.01&qty=1
response: HTTP/1.1 200 OK | charged 499.00

-- 3. Match-and-replace rule: role=customer -> role=admin
GET /admin -> 403 Forbidden | forbidden

-- 4. Repeater: resend history item 0 as POST
repeated -> 405 Method Not Allowed | class: 4xx Client error

-- 5. Intruder (Sniper) on the coupon code
   AAAA       status=200 length=7
   SPRING10   status=200 length=7
   WELCOME41  status=200 length=7
   VIP        status=200 length=7
   FREESHIP   status=200 length=7
   WELCOME43  status=429 length=17
   WELCOME42  status=429 length=17
history size: 11
```

## Steps

1. Read part 1 of the output: the raw response with its status line, headers, blank line and body. Find the hidden `price` field in the HTML. Then print `proxy.history[0][0].to_raw()` to see the matching raw request (request line, headers, blank line).
2. Part 2: the intercept hook changed the price. The vulnerable app charged 0.01; the secure app charged 499.00 because it ignored the client's price.
3. Part 3: a match-and-replace rule turned `role=customer` into `role=admin`. Only the vulnerable app believed it.
4. Part 4: Repeater resent history item 0 with a new method; **405 Method Not Allowed** is a 4xx client error.
5. Part 5: in Intruder results, the right coupon has a **different length** (39 versus 7). On the secure app the last guesses get **429**, so the right code is never confirmed. Discuss: is a rate limit enough? (No: codes should also be long and random, and limits should be per account and per IP.)
6. Write a response hook that removes the `Set-Cookie` header and see what breaks.
7. Add a "Battering ram" mode to `intruder_sniper` that fills several positions with the same payload.

## Run the real tool (hedged)

In the course lab or a local training app: open Burp's embedded browser, browse the checkout, then **Proxy > Intercept** to change the price, **Match and replace** for the role cookie, **Repeater** to replay, and **Intruder > Sniper** with a short payload list (Community edition throttles Intruder). Step-by-step notes: [real-tools/burp-suite.md](../../real-tools/burp-suite.md). ZAP (Fuzzer add-on) and mitmproxy (Python scripts) can do the same.

## What you learned

- HTTP is plain text; anything the browser sends can be changed after the browser's own checks.
- Hidden fields, disabled buttons, client-side validation and role cookies are **not** security controls.
- Response **length** and **status** differences are how testers spot interesting results in bulk.
- Server-side lookups, server-side sessions and rate limits (429 with `Retry-After`) are the fixes.
