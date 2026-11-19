# Lab: The eight secure design principles as vulnerable vs principled code

**Course topics:** [CTMP 5] "Exploring Principles of Secure Design with Examples" and the eight principles. Lesson: [01 Secure design principles](../../01-secure-design-principles.md).

**Time:** 60 minutes. **Tests:** 8 (one per principle), all offline. **Safety:** fictional users and data; the HMAC key is random per run; SQLite runs in memory. Only test systems you own or have written permission to test.

## Goal

See each principle as code: the same small feature written twice, and the same attack run against both. The attack works on the vulnerable version and fails on the principled one.

## Concept

[principles.py](principles.py):

| Principle | Vulnerable | Principled | Attack in the test |
|---|---|---|---|
| Economy of mechanism | `ManyPathAuth` (cookie, API key, legacy header) | `OnePathAuth` (one bearer-token lookup) | send `X-Internal-User: admin` |
| Fail-safe defaults | `allowed_fail_open` (`except: return True`) | `allowed_fail_safe` (deny unknown) | user with no role deletes |
| Complete mediation | `CachedAuthz` (snapshot at login) | `MediatedAuthz` (check every time) | act after access is revoked |
| Open design | `obscure_token` (base64 of `uid:1`) | `open_token` (HMAC-SHA256, secret key) | forge a token knowing the format |
| Separation of privilege | `refund_single_key` | `refund_two_person` (two distinct approvers above a threshold) | requester approves own 50k refund |
| Least privilege | `report_db(False)` (owner connection) | `report_db(True)` (read-only SQLite authorizer) | ad-hoc report runs `DELETE` |
| Least common mechanism | `SharedReportCache` (key = report name) | `TenantReportCache` (key = tenant + report) | tenant B asks for "revenue" |
| Psychological acceptability | `complexity_policy` (8+ chars, 4 classes) | `usable_policy` (15+ chars, blocklist) | `Summer2026!` and a 4-word passphrase |

**DBA note:** `report_db(True)` uses SQLite's `set_authorizer` to allow only reads, the in-process equivalent of `GRANT SELECT ON orders TO report_user`.

## Steps

```text
.venv/Scripts/python appsec-course/07-secure-design-principles-and-case-studies/labs/secure-design-principles/demo.py
.venv/Scripts/python -m pytest appsec-course/07-secure-design-principles-and-case-studies/labs/secure-design-principles -q -p no:cacheprovider
```

1. Run the demo and read each row: same attack, different design.
2. Add a fourth path to `ManyPathAuth` (a query parameter `?as=`). How would a reviewer find it? Why is it impossible in `OnePathAuth`?
3. Make `MediatedAuthz` faster with a cache that expires after 5 seconds. Which principle are you trading, and how would you invalidate on revoke?
4. Change the refund threshold to 0. What is the operational cost (psychological acceptability) of two approvals for every refund?

## Expected output (real run of demo.py)

```text
Principle                    Attack / input                       Vulnerable                   Principled
Economy of mechanism         send X-Internal-User: admin          admin                        None
Fail-safe defaults           user with no role deletes            True                         False
Complete mediation           delete after access revoked          True                         False
Open design                  forge token for user 1               1                            None
Separation of privilege      requester approves own 50k refund    True                         False
Least privilege              ad-hoc report runs DELETE            deleted, 0 rows left         denied (not authorized)
Least common mechanism       globex asks for 'revenue'            revenue for acme             revenue for globex
Psychological acceptability  password 'Summer2026!'               True                         False
Psychological acceptability  passphrase of 4 words                False                        True
```

## Run the real tool (hedged)

These principles are checked in **design reviews** more than by tools. Tools that help: Semgrep/CodeQL rules for fail-open `except` blocks and multiple auth paths; IAM Access Analyzer and `kubectl auth can-i --list` for least privilege; Oracle `DBA_SYS_PRIVS` / `DBA_TAB_PRIVS` reviews for database accounts.

## What you learned

- Each principle prevents a concrete, testable attack.
- The principled version is usually **simpler**, not more complex.
- Principles trade against each other and against usability; record the trade-off as a design decision.
