# Lab: Using BDD security to codify threats

**Course exercise:** "Using BDD security to codify threats." Lessons: [02 section 4 BDD security](../../02-threat-modeling-tools-and-ci-cd.md#4-bdd-security-codifying-threats-as-executable-specs). Related: the sibling BDD-style lab in [chapter 02](../../../02-tools-pipelines-and-secure-sdlc/README.md) (this one is self-contained and does not need it).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** the "application" is a Python function in [app_sim.py](app_sim.py). No server, no socket, no scanning of anything real.

> **Outdated to current.** **BDD-Security** (Continuum Security, later IriusRisk) appears unmaintained since about 2022 and **Gauntlt** is old (verify). The *idea* is current. Use **pytest-bdd** or **behave**, or ZAP Automation Framework tests. See [real-tools/bdd-and-asvs.md](../../real-tools/bdd-and-asvs.md).

## What it does

- [features/authentication.feature](features/authentication.feature) and [features/injection_and_headers.feature](features/injection_and_headers.feature) hold **Gherkin scenarios**. Each one names the **threat id** it covers (T-01, T-02, T-04, T-06, T-09, T-10).
- [bddlite.py](bddlite.py) is a runner of about 150 lines: Feature, Background, Scenario, **Scenario Outline with Examples**, tags (`@wip` is skipped), and `Given/When/Then/And/But`.
- [steps.py](steps.py) turns each phrase into Python (regex step definitions).
- [app_sim.py](app_sim.py) is the target. `App()` is the secure version; `App(vulnerable=True)` has realistic mistakes: no lockout, "no such user" message, SQL error leak, missing headers, weak cookie flags, exposed `/admin`.
- **Undefined steps fail the run.** A scenario that silently does nothing is the worst kind of security test.

## Run

```text
.venv/Scripts/python devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/demo.py
.venv/Scripts/python -m pytest devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats -v
```

## Expected output (real run)

```text
== SECURE app
PASSED    Account locks after repeated failures (threat T-01 credential guessing)
PASSED    Unknown users and wrong passwords look the same (threat T-09 user enumeration)
PASSED    Session cookie has protective flags (threat T-02 session theft)
PASSED    Injection payloads never reach the database as code (threat T-10) [' OR '1'='1]
PASSED    Injection payloads never reach the database as code (threat T-10) ["; DROP TABLE users]
PASSED    Injection payloads never reach the database as code (threat T-10) [<script>x</script>]
PASSED    Hardening headers are present (threat T-04)
PASSED    Admin area is not exposed to anonymous users (threat T-06)
SKIPPED   Rate limit on search (not implemented yet, skipped by tag)  -> tag @wip
exit code: 0
== VULNERABLE app
FAILED    Account locks after repeated failures (threat T-01 credential guessing)  -> expected status 429, got 200
FAILED    Unknown users and wrong passwords look the same (threat T-09 user enumeration)  -> body leaked 'no such user': 'no such user'
FAILED    Session cookie has protective flags (threat T-02 session theft)  -> cookie sid lacks ['Secure', 'HttpOnly', 'SameSite']
FAILED    Injection payloads never reach the database as code (threat T-10) [' OR '1'='1]  -> status was 500, which must not happen
FAILED    Injection payloads never reach the database as code (threat T-10) ["; DROP TABLE users]  -> status was 500, which must not happen
PASSED    Injection payloads never reach the database as code (threat T-10) [<script>x</script>]
FAILED    Hardening headers are present (threat T-04)  -> header X-Content-Type-Options is None, expected 'nosniff'
FAILED    Admin area is not exposed to anonymous users (threat T-06)  -> expected status 404, got 200
SKIPPED   Rate limit on search (not implemented yet, skipped by tag)  -> tag @wip
exit code: 1
```

## Steps

1. Compare the two runs: the same scenarios pass on the secure app and fail on the vulnerable one, with a message that says what leaked.
2. The `@wip` scenario ("rate limit on search") is skipped. In `test_skip_tags_can_be_changed` it runs and fails, which shows the gap is real, not hidden.
3. Add an example row to the SQL injection outline, for example `1; SELECT pg_sleep(5)`, and run again.
4. Add a scenario: "Given a registered user alice, When I search for a script tag, Then the response body does not contain the raw tag". Notice the secure app encodes `<`.
5. Write a new step with a typo in the phrase and see `UNDEFINED` in the output.

## Why BDD for security

- The scenario is the **abuse case from the threat model** in plain words. A security person and a product owner can both review it.
- It runs in CI on every build, so a regression in lockout or headers is caught the same day.
- The scenario name keeps the link to the threat id, which feeds the traceability report in the [requirements lab](../security-requirements-as-code/README.md).

## Limits

- BDD checks the **specific** abuse cases you thought of. It does not find unknown bugs; that is the job of SAST and DAST.
- This is a tiny runner. Real frameworks have hooks, reports, parallel runs and a large step ecosystem.

## Run the real tool (hedged)

Write the same steps with **pytest-bdd** (feature files stay the same) and point the client at a local or staging copy of your application. See the sketch in [real-tools/bdd-and-asvs.md](../../real-tools/bdd-and-asvs.md). Do not run attack steps against production or third-party systems.
