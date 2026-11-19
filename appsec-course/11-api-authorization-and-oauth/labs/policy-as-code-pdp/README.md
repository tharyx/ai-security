# Lab: Decoupling authorization decisions with policy as code

**Course topics:** "Decoupling Authorization Decisions With Policy As Code", "Attribute-Based Access Control (ABAC) with Roles, and Relations". Lesson: [01 section 4](../../01-authorization-models-and-policy-as-code.md#4-decoupling-authorization-decisions-with-policy-as-code).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** in-memory data only. Only test systems you own or have written permission to test.

## Goal

Move "who may do what" out of the handler code into a **policy file** that a small **policy decision point (PDP)** evaluates, with unit tests for the policy itself, the way OPA/Rego or Cedar are used.

## Concept

```text
request -> API handler (PEP: policy enforcement point)
              |  decide(subject, action, resource, env)
              v
           PDP  <- policy.json (version-controlled, reviewed, tested)
              |
           allow / deny + matched rule ids (for the audit log)
```

- **Deny by default.** No matching rule means deny.
- **Deny overrides allow.** A suspended admin is still denied.
- **Policy tests** run in CI like `opa test`.
- **Lint** rejects typos (an unknown operator would otherwise never match, so the rule silently does nothing).

[pdp.py](pdp.py) contains the PDP, a policy linter, a policy test runner, a hard-coded handler (the anti-pattern) and a decoupled handler. The policy is [fixtures/policy.json](fixtures/policy.json); its tests are [fixtures/policy_tests.json](fixtures/policy_tests.json).

## Steps

1. Run the demo. All 7 policy tests pass; alice can read trip `t-1` (hers) but not `t-2` (BOLA blocked by policy, not by code).
2. Add a rule that lets a rider's **emergency contact** read the rider's trip (`resource.emergency_contact_id == subject.id`). Add a test case to the fixture first, watch it fail, then add the rule.
3. Change `"=="` to `"="` in one rule and run the tests: lint stops the bad policy before it is deployed.
4. Compare `hardcoded_get_trip` with `pep_get_trip`. Which one would you rather review when the 40th endpoint is added?

## Run

```text
.venv/Scripts/python appsec-course/11-api-authorization-and-oauth/labs/policy-as-code-pdp/demo.py
.venv/Scripts/python -m pytest appsec-course/11-api-authorization-and-oauth/labs/policy-as-code-pdp -q -p no:cacheprovider
```

## Expected output (real run)

```text
== Policy tests (like `opa test`) ==
7/7 passed

== API handler asks the PDP ==
GET /trips/t-1 as alice -> 200 matched=['owner-reads-own-trip'] reason='allowed by rule'
GET /trips/t-2 as alice -> 403 matched=[] reason='no rule matched; default deny'

== Change behaviour by changing policy, not code ==
support reads t-1 (old policy): 200
support reads t-1 (new policy): 403

== Lint catches a typo before deploy ==
PolicyError: x: bad condition ['subject.id', '=', 'u-1']
```

## Run the real tool (hedged)

The same idea with **OPA** (verify flags with `opa --help`):

```rego
package trips.authz
import rego.v1

default allow := false

allow if {
    input.action == "trip:read"
    input.resource.owner_id == input.subject.id
}
```

```text
opa eval -d policy.rego -i input.json "data.trips.authz.allow"
opa test . -v
```

**Cedar** (AWS, open source; used by Amazon Verified Permissions) writes the same rule as `permit (principal, action == Action::"trip:read", resource) when { resource.owner == principal };`. **Casbin** and **OpenFGA** are other options. The OpenID Foundation's **AuthZEN** working group is standardising the PEP to PDP API (check its current status).

## What you learned

- A PDP gives one place to review, test and log authorization decisions.
- Policies need the same engineering as code: review, lint, unit tests, versioning.
- The handler still has to **call** the PDP on every route: missing that call is BFLA.
