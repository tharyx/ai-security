# Lab: Exploiting mass assignment vulnerabilities

**Course exercise:** "Exploiting Mass Assignment Vulnerabilities". Lesson: [02 section 8](../../02-injection-vulnerabilities.md#8-mass-assignment-issues). In the OWASP API Top 10 2023 this is part of **API3 BOPLA** ([chapter 13](../../../13-owasp-api-top-10-and-other-threats/README.md)).

**Time:** 30 minutes. **Tests:** 5, all offline. **Safety:** an in-memory dataclass store. Only test systems you own or have written permission to test.

## Goal

Send extra JSON fields (`is_admin`, `credit`, `email_verified`) to a profile update and watch the vulnerable API save them. Then use an input schema that rejects them.

## Concept

Frameworks make it easy to bind a request body straight onto a model (`Model(**body)`, `user.update(req.body)`, Rails `params.permit!`, Spring data binding). The client then controls **every** field, including ones the UI never shows.

**DBA view:** it is like an `UPDATE users SET <every column the client names>`: an `UPDATE` grant on the whole table instead of on two columns.

Defences, in order of strength:

1. **Input DTO / schema per operation** with an allowlist of fields, types and lengths.
2. **Reject unknown fields** (422) rather than silently dropping them, so tests and monitoring notice probing.
3. **Server-owned fields** (`role`, `credit`, `email_verified`) change only through their own workflow.
4. **Output schema** too, so internal fields are not leaked (the read side of BOPLA).

## Steps

1. Run the demo.
2. In [mass_assign.py](mass_assign.py), add `"email_verified": (bool, 0, 0)` to `PROFILE_SCHEMA`. Which test breaks, and what attack does that re-open?
3. Find the field names an attacker would try: read the GET response, the OpenAPI spec, JavaScript bundles, or guess (`isAdmin`, `is_admin`, `role`, `roles[]`, `admin`).

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/mass-assignment/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/mass-assignment -q -p no:cacheprovider
```

## Expected output (real run)

```text
PATCH /users/1 body: {"display_name": "Alice", "is_admin": true, "credit": 100000, "email_verified": true}
vulnerable -> (200, {'id': 1, 'email': 'alice@lab.example', 'display_name': 'Alice', 'is_admin': True, 'credit': 100000, 'email_verified': True})
secure     -> (422, {'error': "unknown or read-only fields: ['credit', 'email_verified', 'is_admin']"})
secure, legit change -> (200, {'id': 1, 'email': 'alice@lab.example', 'display_name': 'Alice K'})
```

## Run the real tool (hedged)

In Burp Repeater, take a legitimate `PATCH /users/me` and add one candidate field at a time; then `GET /users/me` to see whether it stuck. The **Param Miner** extension can guess hidden parameters (check the BApp Store).

## What you learned

- Never bind request bodies onto persistence models.
- Allowlists per operation, rejection of unknown fields, and separate output schemas close both sides of BOPLA.
