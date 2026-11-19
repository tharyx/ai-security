# Lab: Enumerating user accounts from an API, and the uniform-response fix

**Course item:** "Enumerating User Accounts From an AP[I]". **Lesson:** [03 section 5](../../03-openapi-burp-and-reconnaissance.md#5-enumerating-user-accounts-from-an-api).

**Time:** 30 minutes. **Tests:** 6, offline. **Safety:** two in-process auth services with toy users; timing is simulated with a counted "work" value, not real sleeps. Only test systems you own or have written permission to test.

## Goal

Detect account existence from differences in status, message and timing; then make the endpoint uniform so the same attack learns nothing.

## Files

| File | Role |
|---|---|
| [userenum.py](userenum.py) | `VulnerableAuth` and `SecureAuth` (login, register, reset), `enumerate_users` |
| [demo.py](demo.py) | runs the attack against both |
| [test_aps_ch09_user_enumeration.py](test_aps_ch09_user_enumeration.py) | the tests |

`enumerate_users` first learns the "no such user" fingerprint from an obviously fake name, then flags any candidate whose response differs in status, message or work.

## Run

```text
.venv/Scripts/python appsec-course/09-api-tooling-and-reconnaissance/labs/user-enumeration/demo.py
.venv/Scripts/python -m pytest appsec-course/09-api-tooling-and-reconnaissance/labs/user-enumeration -q
```

## Real output

```text
=== VULNERABLE API (responses differ) ===
  alice  -> 401  'Wrong password'                    work=10
  carol  -> 404  'No account with that username'     work=1
  bob    -> 401  'Wrong password'                    work=10
  dave   -> 404  'No account with that username'     work=1
  enumerated users: ['alice', 'bob']

=== SECURE API (uniform response) ===
  alice  -> 401  'If the credentials are valid you will be signed in'    work=10
  carol  -> 401  'If the credentials are valid you will be signed in'    work=10
  bob    -> 401  'If the credentials are valid you will be signed in'    work=10
  dave   -> 401  'If the credentials are valid you will be signed in'    work=10
  enumerated users: []
```

## Steps

1. In `VulnerableAuth.login`, fix only the status code. Run the attack: still enumerable (message and timing differ).
2. Fix the message too. Still enumerable by timing (`work_units`). This is why `SecureAuth` always performs the hash check, against a dummy value when the user is missing.
3. Test `register` and `reset` on both classes. Registration is the hardest to make uniform: `SecureAuth` returns 202 and finishes sign-up by email.
4. Write an `enumerate_by_reset` function that uses the reset endpoint and prove it works on the vulnerable class only.
5. Combine with [weak-password-login (ch10)](../../../10-api-authentication/labs/weak-password-login/README.md): enumeration first, then password guessing against only real accounts. Which control in chapter 10 stops the second step?

## Run the real tool (hedged)

In Burp: send a login request to **Intruder**, mark the username, load a short candidate list, and sort results by status, length and response time (Community is throttled). With ffuf:

```bash
ffuf -u https://api.lab/api/v1/login -X POST -H 'Content-Type: application/json' \
     -d '{"username":"FUZZ","password":"wrong"}' -w users.txt -mc all -rate 5
```

Then compare the `Status`, `Size` and `Duration` columns. Only within an agreed scope and rate.

## What you learned

- Enumeration leaks through status, message, size and timing, on login, registration, reset and lookup endpoints.
- The fix is a uniform response plus constant work, backed by rate limits and alerting.
