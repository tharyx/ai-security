# Lab: Registry attacks (open registries, no RBAC)

**Course exercise:** "Attacking Misconfigured Docker Registry". Lessons: [02 registry-based attacks](../../02-container-attack-matrix-image-and-registry-attacks.md#5-registry-based-attacks).

**Time:** 60 minutes. **Safety:** A Python object that mimics Registry API decisions. No sockets.

## What it models

Three registry modes: **open** (no auth), **authenticated but no RBAC** (any valid user can do anything), and **RBAC plus immutable tags**. The attacker steps are catalog enumeration, tag listing, manifest pulls with secret hunting, **pushing over a tag** and deleting an image. Deeper token-scope and TLS coverage lives in [csse attack-docker-registry](../../../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/registry-attacks/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/registry-attacks -v
```

1. Run the demo and compare the four cases.
2. Why does the read-only dev token still hurt in the no-RBAC mode? (Authentication is not authorization.)
3. Under RBAC, can the CI token overwrite a tag? Can it delete? (Neither: 409 and 403.)
4. Add a rule: scan on push. What would it block?

## Expected output (real run)

```text
== open registry, no credentials ==
  enumerate catalog        (200, ['hr/payroll', 'shop/api', 'shop/web'])
  secrets in configs       ['shop/api:1.0 DB_PASSWORD']
  overwrite shop/web:1.0   201
  delete shop/api:1.0      202

== auth but NO RBAC, a read-only dev's token ==
  enumerate catalog        (200, ['hr/payroll', 'shop/api', 'shop/web'])
  secrets in configs       ['shop/api:1.0 DB_PASSWORD']
  overwrite shop/web:1.0   201
  delete shop/api:1.0      202

== RBAC + immutable tags, same dev token ==
  enumerate catalog        (403, 'catalog scope required')
  secrets in configs       ['shop/api:1.0 DB_PASSWORD']
  overwrite shop/web:1.0   403
  delete shop/api:1.0      403

== RBAC + immutable tags, CI token ==
  enumerate catalog        (403, 'catalog scope required')
  secrets in configs       ['shop/api:1.0 DB_PASSWORD']
  overwrite shop/web:1.0   409
  delete shop/api:1.0      403
```

## Think about it

Authentication answers who, RBAC answers what. Immutable tags make a stolen CI token much less useful.

## Run the real tool

Local `registry:2`, Harbor (projects, robot accounts, tag immutability), `curl /v2/_catalog` on your own registry only.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/registry-attacks`.
