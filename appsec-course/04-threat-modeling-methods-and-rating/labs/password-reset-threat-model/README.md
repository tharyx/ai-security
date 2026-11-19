# Lab: Threat modeling a password reset workflow (threat → requirement → test)

**Course exercises:** [CTMP 2] Threat Modeling a Password Reset Workflow; [CSC 4] Threat modeling for a Password Reset workflow, Writing Security Requirements for Threat Modeling. Lessons: [06 Password reset](../../06-password-reset-workflow.md), [01 section 5](../../01-security-requirements-and-diagramming.md#5-writing-security-requirements-for-threat-modeling).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** both services are in-process toy classes with fictional users; the attacks only target this lab's own code. No email is sent and no network is used. Only test systems you own or have written permission to test.

## Goal

Show that every threat in the password-reset model is real on a vulnerable implementation, write a security requirement for each, and prove the secure implementation meets all of them.

## Concept

| File | Role |
|---|---|
| [reset_vulnerable.py](reset_vulnerable.py) | md5(email + time) token, no expiry, reusable, stored and logged in clear, "no account with that email", link from the Host header, sessions kept, no password policy, no rate limit, no audit |
| [reset_secure.py](reset_secure.py) | `secrets.token_urlsafe(32)`, SHA-256 hash at rest, 15-minute single use, older tokens invalidated, uniform 202 response, fixed base URL, no token in logs, 3 emails per hour, length 15 + blocklist, sessions revoked, audit event |
| [attacks.py](attacks.py) | 11 attacks, each returns True if it worked (predict token, enumerate users, host header poisoning, replay, expired token, DB dump, token in logs, session survives, weak password, mailbox flood, no audit) |
| [requirements.py](requirements.py) | SR-01 to SR-11: STRIDE letter, threat, requirement text, and the attack that must fail |

`requirements.verify(ServiceClass)` runs each attack against a fresh instance with a controllable clock.

## Steps

1. Run the demo: all 11 requirements are violated by the vulnerable service and met by the secure one.
2. Read `predict_token()` in `attacks.py`: the attacker triggers a reset for the victim and tries seven guesses around the current second. Why does it fail on the secure service?
3. Break the secure service on purpose: set `TOKEN_TTL = 3 * 24 * 3600`. Which requirement fails? Restore it.
4. Remove `user["sessions"].clear()` from `reset_secure.py` and run the tests: SR-08 fails.
5. Write SR-12 for a threat from lesson 06 that is not covered (for example: notify the user by email after a successful reset) with an attack function and a test.

## Run

```text
.venv/Scripts/python appsec-course/04-threat-modeling-methods-and-rating/labs/password-reset-threat-model/demo.py
.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating/labs/password-reset-threat-model -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
Req    STRIDE vulnerable  secure  Requirement
SR-01  S      VIOLATED    met     Generate reset tokens with a CSPRNG (at least 128 bits of entropy).
SR-02  I      VIOLATED    met     Return the same status and message whether or not the account exists.
SR-03  T      VIOLATED    met     Build reset links from a configured base URL, never from request headers.
SR-04  S      VIOLATED    met     Reset tokens are single use and older tokens are invalidated.
SR-05  S      VIOLATED    met     Reset tokens expire after at most 15 minutes.
SR-06  I      VIOLATED    met     Store only a hash of the reset token.
SR-07  I      VIOLATED    met     Never write reset tokens or links to logs.
SR-08  E      VIOLATED    met     Revoke all sessions and refresh tokens after a password reset.
SR-09  S      VIOLATED    met     Enforce minimum length (15 for single-factor) and a common-password blocklist.
SR-10  D      VIOLATED    met     Send at most 3 reset emails per account per hour.
SR-11  R      VIOLATED    met     Write an audit event (no secrets) for every completed reset.

vulnerable: 0/11 requirements met
secure:     11/11 requirements met
```

## Run the real tool (hedged)

Against **your own** staging app: use Burp Suite or ZAP to (a) send two `/forgot` requests and compare tokens, (b) change the `Host` and `X-Forwarded-Host` headers and inspect the email, (c) replay a used link, (d) compare responses for existing and non-existing emails. ZAP and Burp setup are covered in chapter 09 and [cybersecurity-track 09](../../../../cybersecurity-track/09-pentesting-fundamentals/README.md). Follow the OWASP Forgot Password Cheat Sheet and the WSTG test for weak password reset (verify current IDs).

## What you learned

- A threat model is only useful when each threat becomes a testable requirement.
- Most reset flaws are design decisions (where the link comes from, what is stored, what happens to sessions), not typos.
- The same attack code is both the evidence of the risk and the regression test for the fix.
