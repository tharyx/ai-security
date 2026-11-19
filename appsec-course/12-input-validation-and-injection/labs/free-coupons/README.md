# Lab: Getting free coupons without knowing the coupon code

**Course exercise:** "Getting Free Coupons Without Knowing Coupon Code". Lesson: [03 section 3](../../03-fuzzing-and-brute-forcing.md#3-business-logic-brute-force-the-free-coupon-case). Related OWASP API 2023 items: API4 Unrestricted Resource Consumption and API6 Unrestricted Access to Sensitive Business Flows ([chapter 13](../../../13-owasp-api-top-10-and-other-threats/README.md)).

**Time:** 30 minutes. **Tests:** 6, all offline. **Safety:** an in-memory shop with a simulated clock. Only test systems you own or have written permission to test.

## Goal

Find a valid coupon by brute force, then abuse business logic (reuse and stacking) to make an order nearly free. Then show the controls that stop it.

## Concept

| Weakness | Attack | Control |
|---|---|---|
| Predictable codes (`SAVE` + 3 digits = 1,000 options) | Intruder-style numbers payload | 16 random characters from `secrets` (about 82 bits) |
| No attempt limit | Try all 1,000 | 5 failures per account per 15 min, then `429` (plus per-IP and global limits) |
| Coupon reusable, coupons stack | Apply the same code 10 times | One use per account, one coupon per order |
| No business floor | Total goes to near zero | Server-side minimum total, alerts on unusual discounts |

## Steps

1. Run the demo. Count the requests the vulnerable brute force needed.
2. Raise the secure limit from 5 to 50 failures. Is 50 still safe with 16-character codes? (Yes, the keyspace is huge; the limit matters most for short codes and PINs.)
3. An attacker rotates accounts. What extra signal would you add? (Per-IP/device limits, coupon-endpoint global rate, CAPTCHA as friction, alerting.)

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/free-coupons/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/free-coupons -q -p no:cacheprovider
```

## Expected output (real run)

The coupon code is random, so the request count changes per run.

```text
== VULNERABLE shop ==
brute force SAVE000-SAVE999: found=SAVE059 after 60 requests
after applying it 10 times, total = 28.25 (was 1000.0)
secure-path test with the real code twice: (200, 700.0) (200, 490.0) total 490.0

== SECURE shop ==
brute force SAVE000-SAVE999: found=None after 6 requests
secure-path test with the real code twice: (200, 700.0) (409, 'one coupon per order') total 700.0
```

## Run the real tool (hedged)

In the course lab: capture `POST /cart/coupon` in Burp, send to **Intruder**, mark the digits, use a **Numbers** payload `000`-`999` with min/max integer digits 3, and sort results by status or length. ffuf does the same: `ffuf -X POST -u https://lab/cart/coupon -H "Content-Type: application/json" -d '{"code":"SAVEFUZZ"}' -w nums.txt -fc 404` (verify flags). See [real-tools/fuzzing-tools.md](../../real-tools/fuzzing-tools.md).

## What you learned

- Brute force needs a small keyspace and no rate limit; remove either and it fails.
- Business logic rules (single use, no stacking, floors) must be enforced on the server.
