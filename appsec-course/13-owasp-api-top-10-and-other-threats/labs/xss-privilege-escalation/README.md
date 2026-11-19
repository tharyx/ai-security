# Lab: Privilege escalation with cross-site scripting

**Course topic:** "Privilege Escalation With Cross Site Scripting". Lesson: [03 section 2](../../03-post-exploitation-xss-and-cors.md#2-privilege-escalation-with-cross-site-scripting). XSS prevention (encoding, CSP, Trusted Types) is taught in [chapter 12](../../../12-input-validation-and-injection/04-output-encoding-csp-and-trusted-types.md).

**Time:** 45 minutes. **Tests:** 7, all offline. **Safety:** a simulated browser runs a two-command toy script language (`steal(...)`, `call(...)`), not JavaScript. Session IDs are FAKE. Only test systems you own or have written permission to test.

## Goal

A normal user (mallory) posts a comment with a script. When the admin opens the moderation page, the script runs **as the admin** and promotes mallory to admin. Then test each defence alone to see what it does and does not stop.

## Concept

Stored XSS in an admin-facing page is a privilege escalation: the attacker borrows the admin's session **inside the admin's browser**. Two goals:

1. **Steal the session cookie** (stopped by `HttpOnly`).
2. **Act as the admin from the same origin** (`fetch('/api/admin/...')` with the admin's cookies attached). `HttpOnly` does **not** stop this.

| Defence | Cookie theft | Admin action |
|---|---|---|
| none | stolen | done |
| HttpOnly only | stopped | **still done** |
| CSRF token only | stolen | stopped in this simulation* |
| strict CSP (nonce) | stopped | stopped |
| output encoding | stopped | stopped |

\* In a real browser an XSS payload can usually **read the CSRF token from the page** and send it. The simulation assumes the token is not in the DOM to isolate the idea; do not rely on CSRF tokens against XSS. Encoding (fix the bug) and CSP (contain it) are the real controls, plus re-authentication for sensitive admin actions.

## Steps

1. Run the demo and read the table row by row.
2. Change the payload so it uses `call('GET', ...)`. Which defence matters now? (CSRF requires POST in the secure app.)
3. Add a defence "admin actions need a fresh password re-entry" and test it.

## Run

```text
.venv/Scripts/python appsec-course/13-owasp-api-top-10-and-other-threats/labs/xss-privilege-escalation/demo.py
.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats/labs/xss-privilege-escalation -q -p no:cacheprovider
```

## Expected output (real run)

```text
mallory's comment: Great product!<script>steal(document.cookie); call('POST', '/api/admin/users/mallory/role', 'admin')</script>

defences                   admin cookie stolen   mallory's role after the admin views the page
none                       True                  admin
HttpOnly cookie only       False                 admin
CSRF token only            True                  user
HttpOnly + CSRF token      False                 user
strict CSP only            False                 user
output encoding only       False                 user
all four                   False                 user
```

## Run the real tool (hedged)

In the course lab, use Burp Repeater to store a harmless proof payload (for example one that changes the page title), then view it as an admin in a separate browser profile. **BeEF** and **XSS Hunter** style tools exist for demonstrating impact in authorised tests only.

## What you learned

- XSS in an admin page is admin compromise, even with HttpOnly cookies.
- Fix with output encoding; contain with strict CSP; protect sensitive actions with re-authentication.
