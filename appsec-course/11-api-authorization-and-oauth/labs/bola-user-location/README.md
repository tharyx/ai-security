# Lab: Finding another user's location using BOLA (plus BFLA and privilege escalation)

**Course exercise:** "Finding Another Users Location Using BOLA". Also covers "Misconfigured Permissions", "Broken Function Level Authorization", "Horizontal Privilege Escalation", "Vertical Privilege Escalation" and "Defending Object & Function Level Access". Lesson: [02 Authorization attacks and defenses](../../02-authorization-attacks-and-defenses.md).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** an in-process toy API (no sockets). Session tokens are random and labelled FAKE. Only test systems you own or have written permission to test.

## Goal

Play the attacker against a ride-hailing API: walk user IDs to collect everyone's home location, read another rider's trip, make yourself admin, and call an admin function. Then show that the secure version blocks each attack.

## Concept

| Attack | What the vulnerable code forgot | DBA view |
|---|---|---|
| **BOLA** (API1) | check that the object belongs to the caller | `WHERE user_id = :id` without `AND user_id = :me` |
| **Horizontal escalation** | same, on another object type (trips) | reading a peer's rows |
| **Vertical escalation** | allowlist of writable fields; `role` came from the request body | user runs `GRANT DBA TO me` and it works |
| **BFLA** (API5) | function-level role check on admin routes | `EXECUTE` on an admin package granted to `PUBLIC` |
| **Misconfigured permission** | an admin route marked public in the route table | a public synonym pointing to a sensitive table |

The secure version adds an **object check** in each handler, a **function check** in the router, an **allowlist** of writable fields, **deny by default** in the route table, and returns **404** (not 403) for objects you may not see, so IDs cannot be probed.

## Steps

1. Run the demo and compare the two blocks line by line.
2. Open [location_api.py](location_api.py) and find the single `if self.secure and ...` line that stops each attack.
3. Remove the object check from `get_location` in secure mode. Which test fails? That test is your regression test for BOLA.
4. Change user IDs to random UUIDs. Does that fix BOLA? (No: IDs leak in URLs, logs and other responses. Unpredictable IDs only slow down enumeration.)
5. Add a "share my live location with bob" feature: model it as a relation (see the [authz-models lab](../authz-models/README.md) ReBAC block) and let the object check consult it.

## Run

```text
.venv/Scripts/python appsec-course/11-api-authorization-and-oauth/labs/bola-user-location/demo.py
.venv/Scripts/python -m pytest appsec-course/11-api-authorization-and-oauth/labs/bola-user-location -q -p no:cacheprovider
```

## Expected output (real run)

```text
===== VULNERABLE API, logged in as alice (id 101, rider) =====
1 BOLA  : enumerate /users/{id}/location for ids 1..103 -> {1: 'HQ, 12.9716,77.5946', 101: '12.9352,77.6245', 102: '28.6139,77.2090', 103: '19.0760,72.8777'}
2 horiz : GET /trips/T-5002 (bob's trip) -> 200
3 vert  : PUT /users/101 {role: admin} -> 200 {'id': 101, 'name': 'alice', 'role': 'admin'}
4 BFLA  : DELETE /admin/users/102 -> 204
5 misconf: GET /admin/export with NO token -> 200
   route audit: ['GET ^/api/v1/admin/export$ -> admin_export is PUBLIC but is an admin function']

===== SECURE API, logged in as alice (id 101, rider) =====
1 BOLA  : enumerate /users/{id}/location for ids 1..103 -> {101: '12.9352,77.6245'}
2 horiz : GET /trips/T-5002 (bob's trip) -> 404
3 vert  : PUT /users/101 {role: admin} -> 200 {'id': 101, 'name': 'alice', 'role': 'rider'}
4 BFLA  : DELETE /admin/users/102 -> 403
5 misconf: GET /admin/export with NO token -> 401
   route audit: clean
```

## Run the real tool (hedged)

In the course lab, log in as two users in **Burp Suite**, send user A's request to Repeater and replace A's ID with B's, or use Intruder with a number payload over the ID. The **Autorize** and **AuthMatrix** Burp extensions replay every request with a second user's session and flag responses that should have been denied (check the BApp Store for current versions). See [real-tools/authorization-testing-tools.md](../../real-tools/authorization-testing-tools.md).

## What you learned

- Authentication tells you **who**; every handler must still ask **may this user touch this object and this function**.
- Hiding admin buttons in the UI is not access control.
- Fix BOLA centrally (a PDP or a data-layer filter like VPD) so a new endpoint cannot forget it.
