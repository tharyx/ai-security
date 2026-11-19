# Lab: Password reset workflow flaws and a secure reset

**Course items:** "Password Reset Workflows", "Secure Authentication Workflows". **Lessons:** [02 section 8](../../02-authentication-attacks.md#8-password-reset-workflows), [03 section 1](../../03-authentication-defenses-and-token-storage.md#1-authentication-defenses-and-secure-authentication-workflows).

**Time:** 40 minutes. **Tests:** 7, offline. **Safety:** in-process reset services; "emails" go to a Python list; time is a number you pass in. Only test systems you own or have written permission to test.

## Goal

Take over an account through a flawed reset flow four different ways, then confirm the secure flow blocks each.

| Flaw in `VulnerableReset` | Fix in `SecureReset` |
|---|---|
| token = `md5(username + minute)`: predictable | `secrets.token_urlsafe(32)` |
| token never expires and can be reused | 15-minute TTL, single use, other tokens revoked |
| link built from the client's `Host` header | link built from configured `BASE_URL` |
| "unknown user" vs "link sent" | one uniform message |
| token stored as-is | only `sha256(token)` stored |
| any new password accepted | at least 15 characters |

Files: [reset.py](reset.py), [demo.py](demo.py), [test_aps_ch10_password_reset.py](test_aps_ch10_password_reset.py).

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/password-reset-workflow/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/password-reset-workflow -q
```

## Real output (the secure token changes each run)

```text
=== Vulnerable reset ===
  request(ghost): unknown user
  request(alice, Host: evil.attacker.example): reset link sent
  emailed link : https://evil.attacker.example/reset?token=01dff9c3ac4c
  attacker-predicted token: 01dff9c3ac4c
  confirm(guess) -> True | alice's password now: attacker-pw
  reuse 10 days later -> True

=== Secure reset ===
  request(ghost): If that account exists, a reset link was sent
  request(alice): If that account exists, a reset link was sent
  emailed link : https://shop.lab.example/reset?token=4RwJT275YUfJQWtF1QsDYxW...
  predicted token works? -> False
  real token, first use -> True
  same token, reuse     -> False
```

## Steps

1. Host-header poisoning: who receives the email, and whose server receives the click? (The victim gets the email; the attacker's server receives the token when the victim clicks.)
2. Add rate limiting to `SecureReset.request` (per account and per IP) so the inbox cannot be flooded.
3. Add a notification to the old email on successful reset, and invalidate sessions (keep a `sessions` dict and clear the user's entries).
4. The secure flow compares a hash with `hmac.compare_digest`. Why hash the token at rest at all? (A database leak should not give working reset links.)
5. Add a second factor: if the user has MFA, `confirm` must also receive a valid TOTP (simulate with a fixed lab code).

## Run the real tool (hedged)

In your course lab: request a reset through Burp, change the `Host` (and `X-Forwarded-Host`) header in Repeater and check the emailed link; request two resets and compare tokens for patterns; try the same token twice and after the stated expiry. Only on the lab application.

## What you learned

- Reset tokens must be random, short-lived, single-use and stored hashed.
- Never build security links from request headers.
- The reset flow must be as uniform, throttled and monitored as the login.
