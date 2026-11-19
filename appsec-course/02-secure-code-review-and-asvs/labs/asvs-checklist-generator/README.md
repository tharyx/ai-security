# Lab: Creating an application checklist from OWASP ASVS

**Course topics:** Creating Checklists with OWASP ASVS; Using ASVS to Secure Applications & APIs. Lesson: [03 OWASP ASVS](../../03-owasp-asvs.md#4-creating-checklists-with-owasp-asvs).

**Time:** 45 minutes. **Tests:** 12, all offline. **Safety:** JSON and CSV fixtures only.

> **About the fixture.** [fixtures/asvs5_sample.json](fixtures/asvs5_sample.json) is a small **ASVS-5-like sample**: chapter numbers and names follow ASVS 5.0.0 (verify at source), but the requirement texts are short paraphrases written for this lab and the `ref` values (`V6.S2` and so on) are **sample references, not official requirement ids**. Use `load_csv()` with the official export for real work.

## Goal

Turn the ASVS catalogue into a checklist for one specific application: choose a level, filter by features, assign stable ids, attach evidence, measure, and gate.

## Concept

[asvs_checklist.py](asvs_checklist.py):

| Function | Does |
|---|---|
| `load_sample(path)` / `load_csv(path, cols)` | read requirements; `cols` maps your CSV's column names |
| `select(reqs, level, features)` | keep items with `level <= target` and a matching feature (or `all`) |
| `internal_id(ref)` | stable id `APS-<ref>` that survives selection changes |
| `apply_results(items, results)` | status `pass`/`fail`/`na`/`untested` plus evidence |
| `summary(items)` | counts, tested percentage, passing percentage (n/a excluded) |
| `gate(items)` | 1 on any `fail` or any untested **L1** item |
| `to_markdown`, `to_csv` | the checklist for people and for spreadsheets |

Fixtures: two app profiles ([toy shop](fixtures/profile_shop.json), L2; [partner API](fixtures/profile_partner_api.json), L1), [results for the shop](fixtures/results_shop.json) (evidence points at this course's labs) and an [official-style CSV](fixtures/official_like.csv) to test the importer.

## Run

```text
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/asvs-checklist-generator/demo.py
.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs/labs/asvs-checklist-generator -q -p no:cacheprovider
```

## Expected output (real run)

```text
sample requirements loaded: 27

Partner stock API (machine-to-machine, JWT access tokens, OAuth client): level 1, 11 requirements apply
  ids: APS-V1-S1, APS-V1-S3, APS-V2-S1, APS-V4-S1, APS-V7-S1, APS-V8-S1, APS-V8-S2, APS-V9-S1, APS-V10-S1, APS-V12-S1, APS-V13-S1

Toy shop (web + JSON API, cookie sessions, passwords): level 2, 23 requirements apply
  ids: APS-V1-S1, APS-V1-S2, APS-V1-S3, APS-V2-S1, APS-V2-S2, APS-V3-S1, APS-V3-S2, APS-V3-S3, APS-V4-S1, APS-V4-S2, APS-V6-S1, APS-V6-S2, APS-V6-S3, APS-V6-S4, APS-V7-S1, APS-V8-S1, APS-V8-S2, APS-V11-S1, APS-V12-S1, APS-V13-S1, APS-V13-S2, APS-V14-S1, APS-V16-S1

# ASVS checklist: Toy shop (web + JSON API, cookie sessions, passwords)

## V1 Encoding and Sanitization

- [x] **APS-V1-S1** L1 [V1.S1] Database queries use parameterized queries, an ORM used safely, or equivalent protection; data is never concatenated into query text. (evidence: test_aps_ch02_sqli_review_and_fix.py)
- [x] **APS-V1-S2** L1 [V1.S2] Output is encoded for the context it is written into (HTML body, attribute, JavaScript, URL, CSS). (evidence: test_aps_ch02_xss_review_and_fix.py)
- [x] **APS-V1-S3** L1 [V1.S3] Operating system commands are not built from user input; if unavoidable, arguments are passed without a shell. (evidence: ch01 vulnerable-shop: argv mode test)

## V2 Validation and Business Logic

- [x] **APS-V2-S1** L1 [V2.S1] Input is validated against an allowlist of expected type, length, range and format on a trusted service layer. (evidence: test_aps_ch02_input_validation_regex.py)
- [x] **APS-V2-S2** L2 [V2.S2] Business logic limits (quantities, prices, step order) are enforced on the server. (evidence: ch01 intercepting-proxy: server-side price)

## V3 Web Frontend Security

- [x] **APS-V3-S1** L1 [V3.S1] Session cookies set Secure, HttpOnly and an appropriate SameSite value; the __Host- prefix is used where possible. (evidence: ch01 cookie flags test)
- [x] **APS-V3-S2** L2 [V3.S2] A Content Security Policy restricts script sources and sets object-src 'none' and base-uri. (evidence: ch01 misconfig scan)
- [x] **APS-V3-S3** L2 [V3.S3] Framing by other origins is controlled with CSP frame-ancestors. (evidence: CSP frame-ancestors 'none')

## V4 API and Web Service

- [ ] FAIL **APS-V4-S1** L1 [V4.S1] API responses set a correct Content-Type, and CORS allows only trusted origins (never a reflected Origin with credentials). (evidence: review note: CORS not configured yet for the JSON API)
- [ ] **APS-V4-S2** L2 [V4.S2] HTTP methods not used by an endpoint are rejected.

## V6 Authentication

- [x] **APS-V6-S1** L1 [V6.S1] Passwords of at least the policy minimum length are allowed, long passphrases are accepted, and composition rules are not forced. (evidence: password policy review)
- [ ] FAIL **APS-V6-S2** L1 [V6.S2] New passwords are checked against a list of breached or common passwords. (evidence: no breached-password check)
- [x] **APS-V6-S3** L1 [V6.S3] Automated guessing is limited (rate limits, progressive delays or lockout with care for denial of service). (evidence: ch01 coupon 429 test (pattern reused for login))
- [ ] **APS-V6-S4** L2 [V6.S4] Multi-factor authentication is available, preferring phishing-resistant methods.

## V7 Session Management

- [ ] **APS-V7-S1** L1 [V7.S1] A new session token is issued at login, and logout invalidates the session on the server.

## V8 Authorization

- [x] **APS-V8-S1** L1 [V8.S1] Access to each data object is checked against the requesting user (no IDOR/BOLA). (evidence: ch01 IDOR test)
- [x] **APS-V8-S2** L1 [V8.S2] Function-level access control is enforced on the server and denies by default. (evidence: code review AUTHZ001 clean)

## V11 Cryptography

- [ ] FAIL **APS-V11-S1** L2 [V11.S1] Passwords are stored with an approved slow, salted hash (Argon2id, scrypt, bcrypt or PBKDF2 with a suitable work factor). (evidence: toy SHA-256 hash in the lab app)

## V12 Secure Communication

- [x] **APS-V12-S1** L1 [V12.S1] All traffic uses TLS, and certificate validation is never disabled for outbound calls. (evidence: code review CONF004 clean)

## V13 Configuration

- [x] **APS-V13-S1** L1 [V13.S1] Debug features, default accounts and directory listings are disabled in production. (evidence: ch01 misconfig scan)
- [x] **APS-V13-S2** L2 [V13.S2] Secrets are not stored in source code; they come from a secrets manager. (evidence: code review AUTH003 clean)

## V14 Data Protection

- [x] **APS-V14-S1** L2 [V14.S1] Sensitive responses are not cached (Cache-Control: no-store). (evidence: Cache-Control: no-store header)

## V16 Security Logging and Error Handling

- [x] **APS-V16-S1** L2 [V16.S1] Security events are logged without secrets or session tokens, and error pages do not reveal stack traces. (evidence: ch01 secure error page test)

Total 23: pass 17, fail 3, n/a 0, untested 3. Tested 87.0%, passing 73.9%.

summary: {'pass': 17, 'fail': 3, 'na': 0, 'untested': 3, 'total': 23, 'tested_pct': 87.0, 'pass_pct': 73.9}
gate exit code: 1

CSV (first 3 lines):
id,asvs_ref,chapter,level,status,evidence,text
APS-V1-S1,V1.S1,V1,1,pass,test_aps_ch02_sqli_review_and_fix.py,"Database queries use parameterized queries, an ORM used safely, or equivalent protection; data is never concatenated into query text."
APS-V1-S2,V1.S2,V1,1,pass,test_aps_ch02_xss_review_and_fix.py,"Output is encoded for the context it is written into (HTML body, attribute, JavaScript, URL, CSS)."
```

## Steps

1. Compare the two profiles' id lists. Why does the partner API get V9 and V10 items but no V3 cookie item?
2. In the shop checklist, find the three failures and the three untested items. Which untested item makes the gate fail on its own? (`APS-V7-S1`, because it is L1.)
3. Mark `APS-V5-S1` (file upload) as `na` in a copy of the results for a variant of the shop that has uploads disabled. Record the reason in `evidence`.
4. Change the shop profile to level 3 and rerun. Which new item appears?
5. Download the official ASVS 5.0.0 export (see [real-tools/code-review-tools.md](../../real-tools/code-review-tools.md#asvs-machine-readable-files)), adjust the column map, and generate a real checklist for one of your applications.

## Run the real tools (hedged)

- The OWASP ASVS GitHub repository publishes the standard and exports for released versions (verify the location and format).
- Spreadsheets work well for small teams; threat modeling and requirements platforms (chapter 06) can import ASVS.
- For an "as code" approach linked to tests, compare the DevSecOps [requirements-as-code lab](../../../../devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/README.md).

## What you learned

- ASVS is tailored: a level plus the features your app actually has.
- Stable internal ids mapped to ASVS ids protect you from renumbering between ASVS versions.
- A checklist item without evidence is an opinion; attach tests, scans or review notes.
- A CI gate on failed and untested L1 items keeps the checklist alive.
