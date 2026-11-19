# Lab: Authorization models side by side (none, RBAC, DAC, ABAC, ReBAC)

**Course topics:** "Types of Authorization", "No Authorization", "Role-Based Access Control (RBAC)", "Discretionary Access Control (DAC)", "Attribute-Based Access Control (ABAC)", "Relationship-Based Access Control (ReBAC)". Lesson: [01 Authorization models](../../01-authorization-models-and-policy-as-code.md#2-types-of-authorization).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** pure functions over in-memory data. Only test systems you own or have written permission to test.

## Goal

See the same question, "may this subject do this action on this resource?", answered by five models, and find the weakness of each.

## Concept

| Model | Decision is based on | Oracle DBA analogy | Weakness the lab shows |
|---|---|---|---|
| None | "you are logged in" | every user has `SELECT ANY TABLE` | anyone deletes anything |
| RBAC | the user's roles (with a hierarchy) | `GRANT editor TO admin` | coarse: cannot say "only *your* document" |
| DAC | the owner's grants | `GRANT SELECT ON t TO u WITH GRANT OPTION` | privileges spread beyond the owner's control |
| ABAC | attributes of subject, resource, action, environment | VPD predicate built from `SYS_CONTEXT` | many rules; hard to audit without tests |
| ReBAC | relationship tuples (owner, member, parent) | a join over a grants table | needs a graph store; cycles must be bounded |

## Steps

1. Run the demo and read each block.
2. In [authz_models.py](authz_models.py), give `viewer` the permission `doc:write`. Run the tests: the RBAC test fails because every role above it inherits the change. That is the blast radius of a role edit.
3. In the DAC block, `alice` re-grants to `bob`. Change `grant` so that only the owner may grant (ignore `grant_option`). Which test now fails, and is that a better design?
4. Add an ABAC rule "contractors may only read documents with `classification == 0`". Write a test first.
5. Add a ReBAC tuple `("doc:salaries", "viewer", "group:hr#member")` and a member. Check that alice still cannot see it.

## Run

```text
.venv/Scripts/python appsec-course/11-api-authorization-and-oauth/labs/authz-models/demo.py
.venv/Scripts/python -m pytest appsec-course/11-api-authorization-and-oauth/labs/authz-models -q -p no:cacheprovider
```

## Expected output (real run)

```text
== No authorization ==
mallory may delete doc:salaries? True

== RBAC (roles and a role hierarchy) ==
['viewer'] -> ['doc:read']
['editor'] -> ['doc:read', 'doc:write']
['admin'] -> ['doc:delete', 'doc:read', 'doc:write', 'user:manage']

== DAC (owner grants, like GRANT ... WITH GRANT OPTION) ==
bob grants himself read: False
carol grants alice read WITH GRANT OPTION: True
alice re-grants read to bob: True
bob can read now? True (DAC weakness: the owner lost control)

== ABAC (subject, resource, action, environment attributes) ==
alice read eng doc 10:00 -> (True, 'all attribute rules passed')
alice read hr doc -> (False, 'different department')
alice write eng doc 23:00 -> (False, 'writes only in business hours')

== ReBAC (relationship tuples) ==
user:alice viewer of doc:q3-plan? True
user:alice viewer of doc:salaries? False
user:carol viewer of doc:salaries? True
```

## Run the real tool (hedged)

- **OpenFGA** or **SpiceDB** are real ReBAC servers (Zanzibar style). With OpenFGA you write a model, write tuples, then call `check`; the CLI is `fga` (verify commands with `fga --help`).
- **Casbin** supports ACL, RBAC and ABAC models from a config file in many languages.
- **Cedar** (AWS, open source) and **OPA/Rego** express RBAC and ABAC as policy files; see the [policy-as-code lab](../policy-as-code-pdp/README.md).

## What you learned

- "No authorization" is a model too, and it is the most common one behind real API breaches.
- RBAC answers "what kind of user"; ABAC and ReBAC answer "this user and this object". APIs usually need both.
- DAC is flexible but owners lose control once rights are re-granted.
- Every model needs tests, because a wrong rule fails open silently.
