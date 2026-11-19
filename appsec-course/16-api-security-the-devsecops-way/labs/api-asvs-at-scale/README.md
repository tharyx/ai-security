# Lab: API-focused ASVS checklists for a portfolio of APIs, with automated evidence

**Course items:** "OWASP ASVS Framework", "Understanding OWASP ASVS", "Using ASVS To Secure Applications and APIs", "Creating Checklists With OWASP ASVS", "Addressing API Security Issues at Scale". Lessons: [01 ASVS for APIs](../../01-owasp-asvs-for-apis.md), [03 API security at scale](../../03-api-security-at-scale-and-cicd.md). The single-app checklist generator is in [chapter 02](../../../02-secure-code-review-and-asvs/labs/asvs-checklist-generator/README.md); this lab does not repeat it.

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** JSON fixtures only. Only test systems you own or have written permission to test.

> **About the fixture.** [fixtures/asvs_api_requirements.json](fixtures/asvs_api_requirements.json) is an **ASVS-5-like sample**. The chapter names follow ASVS 5.0 (verify at the source), the requirement texts are short paraphrases, and the `ref` values (`V8.S1` and so on) are **sample ids, not official requirement ids**.

## Goal

A security champion rarely owns one API. Turn ASVS into something that works across **many** APIs:

1. Each API gets a checklist that matches its **level** (L1–L3) and **features** (JWT, OAuth, GraphQL, SOAP, webhooks, file upload).
2. Each requirement says **how it is verified** (`sast:`, `sca:`, `dast:`, `test:` or `manual`). The pipeline's results become the **evidence**.
3. A **portfolio** view shows coverage and a gate per API.
4. **Inventory hygiene** findings (no owner, no spec, not behind the gateway, zombie, stale) are reported, because at scale those are the root causes.

## Concept

[asvs_api.py](asvs_api.py): `checklist_for`, `evaluate`, `coverage`, `gate` (fails on any `fail` or untested **L1** item), `inventory_findings`, `portfolio`, `to_markdown`.

Fixtures: the requirement sample, an [inventory of four APIs](fixtures/api_inventory.json) and [pipeline evidence](fixtures/evidence.json).

## Run

```text
.venv/Scripts/python appsec-course/16-api-security-the-devsecops-way/labs/api-asvs-at-scale/demo.py
.venv/Scripts/python -m pytest appsec-course/16-api-security-the-devsecops-way/labs/api-asvs-at-scale -v
```

## Expected output (real run)

```text
1. Inventory hygiene (problems that break security at scale)
   - legacy-soap: no owning team (nobody fixes its findings)
   - legacy-soap: no OpenAPI/GraphQL/WSDL contract in the repo (cannot DAST-scan or diff it)
   - legacy-soap: not behind the API gateway (no central auth, rate limits, headers)
   - legacy-soap: deprecated but still live (zombie API)
   - legacy-soap: last deployed 2021 (unpatched dependencies likely)

2. Portfolio view
   api               L  reqs  pass  fail  untested  manual  verified gate
   orders-api        2    13    12     1         0       0      100% FAIL
   payments-api      3    16    15     0         0       1       94% ok
   catalog-graphql   1     9     8     1         0       0      100% FAIL
   legacy-soap       2    13     0     1        11       1        8% FAIL

3. Checklist for orders-api (Markdown, first rows)
   # ASVS checklist: orders-api (L2)
   
   | Ref | Chapter | L | Requirement | Status | Evidence |
   |---|---|---|---|---|---|
   | V4.S1 | V4 API and Web Service | 1 | HTTP methods are restricted to those each endpoint needs | pass | dast:http-methods |
   | V4.S2 | V4 API and Web Service | 1 | Responses set a correct Content-Type and nosniff | pass | dast:headers |
   | V2.S1 | V2 Validation and Business Logic | 1 | Requests are validated against a schema; unknown fields rejected | pass | test:schema-validation |
   | V2.S2 | V2 Validation and Business Logic | 2 | Business flows have anti-automation limits | pass | test:rate-limit |
   | V1.S1 | V1 Encoding and Sanitization | 1 | Database access uses parameterized queries | pass | sast:sql-injection |
   | V6.S1 | V6 Authentication | 1 | All non-public endpoints require authentication | pass | test:authn-required, dast:unauth-access |
   | V8.S1 | V8 Authorization | 1 | Object-level access is checked on every id route (no BOLA) | fail | test:bola |
   | V8.S2 | V8 Authorization | 2 | Admin functions require an admin permission (no BFLA) | pass | test:bfla |
```

## Steps

1. `orders-api` fails on `V8.S1` because the BOLA test failed. Which lab in this course is that test (chapter 11)? Fix the evidence and rerun.
2. `catalog-graphql` fails on introspection. Which chapter 14 checklist rule catches the same thing in config?
3. `legacy-soap` has 8% verified coverage and five hygiene findings. Write the one-paragraph risk-acceptance or retirement proposal you would send to its (missing) owner's manager.
4. Add a `file-upload` feature to `orders-api` and see which requirement appears.
5. Replace a sample `ref` with a real ASVS 5.0 id from the official CSV (keep your own id stable, put the ASVS id in a field).

## What you learned

- ASVS becomes useful at scale when each requirement has a **verification method** and evidence comes from the pipeline automatically.
- Coverage ("verified %") is as important as pass/fail; untested L1 items must fail the gate.
- Most API risk at scale comes from inventory gaps: unknown owners, missing contracts, bypassed gateways, zombie versions.

## Run the real tool (hedged)

- Download the official ASVS 5.0 CSV/JSON from the OWASP ASVS GitHub releases and import it (chapter 02's `load_csv`).
- **OWASP SecurityRAT** or a spreadsheet for requirement management; **DefectDojo** to collect SAST/SCA/DAST evidence per product (verify maintenance and versions).
- API inventory: your gateway's admin API, cloud API catalogues (AWS API Gateway, Azure API Center), or an API-security platform's discovery from traffic.
