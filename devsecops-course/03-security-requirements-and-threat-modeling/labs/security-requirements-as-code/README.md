# Lab: Automate security requirements as code

**Course exercise:** "Automate security requirements as code." Lessons: [03 Security requirements as code](../../03-security-requirements-as-code.md). Related: [01-ai-security-fundamentals lesson 04](../../../../01-ai-security-fundamentals/04-ai-attack-surface-and-security-requirements.md) (threat to requirement for AI).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** a fictional shop API, JSON config fixtures, no network.

## What it does

- [fixtures/requirements.yaml](fixtures/requirements.yaml) is an **ASVS-style catalog** of 11 requirements. Each has an id, a level, a chapter pointer (chapter names follow ASVS 5.0; verify exact requirement numbers at owasp.org), the **threat** it answers, and the name of a **check**.
- [reqs.py](reqs.py) has a **check registry** (`@check("name")`), `evaluate()`, a gate, and a threat traceability report. A check reads the application config and returns `(passed, detail)`.
- Statuses: `PASS`, `FAIL`, `NO_TEST` (nobody wrote the check) and `OUT_OF_SCOPE` (level above `target_level`).
- **The gate returns 1 unless every in-scope requirement has a passing check.** A missing check is a failure, not a silent skip.
- Two configs: a mostly good one and a weak one.

## Run

```text
.venv/Scripts/python devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/demo.py
.venv/Scripts/python -m pytest devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code -v
```

## Expected output (real run)

```text
== app_config.json
PASS          REQ-AUTH-01   L1 Passwords are at least 12 characters long  [min_length=12]
PASS          REQ-AUTH-02   L2 New passwords are checked against a breached-password list  [breached_check=True]
PASS          REQ-SESS-01   L1 Session cookies are Secure and HttpOnly  [secure=True httponly=True]
PASS          REQ-SESS-02   L2 Sessions expire after at most 30 idle minutes  [idle_timeout_min=30]
PASS          REQ-COMM-01   L1 TLS 1.2 or newer only  [min_version=1.2]
PASS          REQ-CFG-01    L1 Security response headers are set  [all present]
PASS          REQ-LOG-01    L2 Authentication events are logged and passwords are never logged  [log_auth_events=True log_passwords=False]
PASS          REQ-AUTHZ-01  L1 Access is denied by default  [deny_by_default=True]
PASS          REQ-CRYPTO-01 L1 Passwords are stored with a slow password hash  [hash=argon2id]
NO_TEST       REQ-FILE-01   L1 Uploads have a size limit and a type allow-list  [no automated check registered]
OUT_OF_SCOPE  REQ-MFA-01    L3 Administrators use multi-factor authentication  [level 3 > target 2]
gate exit code: 1
== app_config_weak.json
FAIL          REQ-AUTH-01   L1 Passwords are at least 12 characters long  [min_length=8]
FAIL          REQ-AUTH-02   L2 New passwords are checked against a breached-password list  [breached_check=False]
FAIL          REQ-SESS-01   L1 Session cookies are Secure and HttpOnly  [secure=True httponly=False]
FAIL          REQ-SESS-02   L2 Sessions expire after at most 30 idle minutes  [idle_timeout_min=240]
FAIL          REQ-COMM-01   L1 TLS 1.2 or newer only  [min_version=1.0]
FAIL          REQ-CFG-01    L1 Security response headers are set  [missing=Content-Security-Policy]
FAIL          REQ-LOG-01    L2 Authentication events are logged and passwords are never logged  [log_auth_events=True log_passwords=True]
FAIL          REQ-AUTHZ-01  L1 Access is denied by default  [deny_by_default=False]
FAIL          REQ-CRYPTO-01 L1 Passwords are stored with a slow password hash  [hash=md5]
NO_TEST       REQ-FILE-01   L1 Uploads have a size limit and a type allow-list  [no automated check registered]
OUT_OF_SCOPE  REQ-MFA-01    L3 Administrators use multi-factor authentication  [level 3 > target 2]
gate exit code: 1
== write the missing check, run again with the good config
gate exit code: 0
== threat traceability
T-01 credential guessing -> REQ-AUTH-01:PASS, REQ-AUTH-02:PASS, REQ-MFA-01:OUT_OF_SCOPE
T-02 session theft -> REQ-SESS-01:PASS, REQ-SESS-02:PASS
T-03 traffic interception -> REQ-COMM-01:PASS
T-04 content sniffing and script injection -> REQ-CFG-01:PASS
T-05 repudiation -> REQ-LOG-01:PASS
T-06 broken access control -> REQ-AUTHZ-01:PASS
T-07 offline cracking -> REQ-CRYPTO-01:PASS
T-08 malicious upload -> REQ-FILE-01:PASS
```

## Steps

1. Read the first run: the good config passes 9 requirements but the gate still fails on `REQ-FILE-01` (`NO_TEST`). That is the point.
2. Read the weak config: many requirements fail for real reasons (short passwords, no breached-password check, HttpOnly missing, long idle timeout, TLS 1.0, missing headers, md5, no deny-by-default, passwords in logs).
3. The demo registers the missing `upload_limits` check and the gate turns green.
4. Set `target_level: 3` in the YAML and run again: `REQ-MFA-01` is now in scope and has no check, so the gate fails again.
5. Add a new requirement of your own (for example "refresh tokens are rotated"), run, and watch `NO_TEST` appear. Then write the check.
6. Break a check on purpose (change `>= 12` to `>= 0`) and see why you must prove a check can fail.

## Limits

- Configuration checks prove a setting exists, not that the behaviour works. Pair them with behaviour tests such as the [BDD lab](../bdd-security-threats/README.md).
- The catalog is fictional and small. Real ASVS level 2 has far more requirements; start with a subset you can really verify.

## Run the real tool (hedged)

There is no single "ASVS runner". Real projects: keep the catalog in YAML or JSON (import ASVS from the OWASP machine-readable release, verify), tag tests with requirement ids, and have CI check that every id has a passing test result. See [real-tools/bdd-and-asvs.md](../../real-tools/bdd-and-asvs.md).
