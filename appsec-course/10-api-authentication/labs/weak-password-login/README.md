# Lab: Exploiting weak passwords online, stopped by lockout and rate limiting

**Course items:** "Exploiting Broken Authentication With Weak Passwords", "Brute Force", "Account Lockouts", "Rate Limiting". **Lessons:** [02 sections 2 and 3](../../02-authentication-attacks.md#2-brute-force), [03 section 5](../../03-authentication-defenses-and-token-storage.md#5-rate-limiting).

**Time:** 40 minutes. **Tests:** 5, offline. **Safety:** in-process login services, a toy lab password and a 10-word attack list; time is passed in as a number, so nothing sleeps. Only test systems you own or have written permission to test.

## Goal

Crack a weak password with a dictionary against an unprotected login, then stop the same run with a per-account lockout and, separately, with a per-IP token-bucket rate limit.

## Files

| File | Role |
|---|---|
| [weak_login.py](weak_login.py) | `OpenLogin`, `GuardedLogin(max_failures, rate_per_sec, burst)`, `dictionary_attack`, `ATTACK_WORDLIST` |
| [demo.py](demo.py) | runs the attack three times |
| [test_aps_ch10_weak_password_login.py](test_aps_ch10_weak_password_login.py) | the tests |

The attacker fires 100 requests per second (`now += 0.01`).

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/weak-password-login/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/weak-password-login -q
```

## Real output

```text
attacker wordlist: ['123456', 'password', 'qwerty', 'letmein', 'admin', 'welcome', 'monkey', 'dragon', 'sunshine', 'p@ssw0rd']

=== Open login (no lockout, no rate limit) ===
  {'cracked': True, 'password': 'p@ssw0rd', 'tries': 10}

=== Guarded login: lockout after 5 failures ===
  {'cracked': False, 'stopped_by': 'locked', 'tries': 5}

=== Guarded login: per-IP rate limit (burst 3, 1 req/s) ===
  {'cracked': False, 'stopped_by': 'rate_limited', 'tries': 4}
```

## Steps

1. `p@ssw0rd` passes many "complexity" rules (symbol, digit) yet is in every attack list. Explain with NIST's guidance why length and blocklists beat composition rules.
2. **Lockout as DoS:** after the attack, the real user cannot log in either (`test_lockout_stops_the_same_attack`). Change lockout to a growing delay (1s, 2s, 4s...) and add a test.
3. **Spraying:** write `spray(login, users, password)` that tries one password across 20 users from 20 different IPs. Neither control fires. Add a global failure-rate check for the login endpoint to detect it.
4. The rate limiter keys on `ip`. If the app took `ip` from a client-sent `X-Forwarded-For`, how would the attacker bypass it?
5. Return 429 with a `Retry-After` value computed from the bucket.

## Run the real tool (hedged)

Against your course lab login only, at an agreed rate: Burp Intruder (throttled in Community) or ffuf with `-rate` (see [real-tools/auth-testing-tools.md](../../real-tools/auth-testing-tools.md)). Watch for 429 responses and `Retry-After`.

## What you learned

- Weak passwords fall to tiny dictionaries when the login has no throttle.
- Lockout stops one-account guessing but enables DoS and is blind to spraying; rate limits by IP stop fast single sources.
- Combine per-account, per-IP and global limits with MFA and breached-password checks.
