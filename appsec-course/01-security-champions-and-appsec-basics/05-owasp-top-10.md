# Lesson 05: OWASP Top 10 Basics (2021 list, with the 2025 update)

**Syllabus items covered:** [CSC 1] OWASP Top 10 Basics; Broken access control; Cryptographic failures; Injection; Insecure design; Security misconfiguration; Vulnerable and outdated components; Identification and authentication failures; Software and data integrity failures; Security logging and monitoring failures; Server side request forgery.

**Time:** 2 hours. **Lab:** [vulnerable-shop](labs/vulnerable-shop/README.md). **Safety:** in-process toy shop only. Only test systems you own or have written permission to test.

## 1. OWASP Top 10 basics

The **OWASP Top 10** is an awareness document: the ten most important web application risk categories, built from contributed vulnerability data plus a community survey. It is **not** a complete standard (use OWASP ASVS for that, chapter 02) and not a testing checklist on its own. Each category maps to many CWEs.

The course syllabus uses the **2021** list. **OWASP Top 10:2025** has since been published (section 12 below). Learn the 2021 names for the course exam and the 2025 names for work; verify the exact final names at owasp.org/Top10.

For each category below: what it is, a DBA-style picture, an example, and the main defenses.

## 2. Broken access control (A01:2021)

Users act outside their permissions: read another user's record (IDOR/BOLA), call an admin function, change a role, bypass checks by editing a URL or token. **Number 1 in both 2021 and 2025.**

- **DBA picture:** a query that forgot `WHERE owner_id = :me`, or a schema where every app user connects as the owner. Oracle VPD (row-level security) is the database version of object-level authorization.
- **Example:** `GET /orders/2` returns Bob's order to Alice ([lab](labs/vulnerable-shop/README.md), `idor_read_other_order`).
- **Defenses:** deny by default; check authorization on the **server** for every request and every object; centralize checks; return 404 for objects the user may not see; log access-control failures; test with two users.

## 3. Cryptographic failures (A02:2021)

Sensitive data exposed because crypto is missing, weak or misused: HTTP instead of HTTPS, MD5/SHA-1 password hashes, hard-coded keys, ECB mode, predictable random numbers, disabled certificate checks.

- **DBA picture:** backups or data files copied without TDE, or passwords stored in a column in clear text.
- **Defenses:** classify data; TLS everywhere with HSTS; store passwords with Argon2id, scrypt, bcrypt or PBKDF2 (chapter 14); use vetted libraries (AES-GCM, not home-made); keys in a KMS or vault; `secrets` module for tokens, never `random`.

## 4. Injection (A03:2021)

Untrusted data is sent to an interpreter as part of a command: SQL, NoSQL, OS command, LDAP, XPath, template engines. In 2021, **XSS was merged into this category**.

- **DBA picture:** the difference between `EXECUTE IMMEDIATE 'SELECT ... WHERE name = ''' || p_name || ''''` and `EXECUTE IMMEDIATE '... WHERE name = :1' USING p_name`. Bind variables fix both performance (shared cursors) and injection.
- **Examples:** search box UNION injection and `admin'--` login bypass; `ping` tool with `; cat /etc/passwd` ([lab](labs/vulnerable-shop/README.md)).
- **Defenses:** parameterized queries and safe ORM use; avoid calling a shell (pass an argument list); context-aware output encoding for XSS; allowlist validation as an extra layer; least-privilege database accounts. Chapter 02 reviews and fixes SQLi and XSS in code; chapter 12 goes deep.

## 5. Insecure design (A04:2021)

Flaws in the **design** that no amount of perfect code fixes: no rate limit on a coupon endpoint, password reset by "security question", a checkout that trusts a client price, missing tenant separation.

- **Example:** the [intercepting-proxy lab](labs/intercepting-proxy/README.md) checkout that takes the price from a hidden field.
- **Defenses:** threat modeling (chapters 03 to 07), secure design patterns, abuse cases in user stories, reference architectures, limits on business flows.

## 6. Security misconfiguration (A05:2021)

Insecure defaults or settings: debug mode on, default accounts, directory listing, verbose errors, unnecessary features, missing security headers, permissive CORS, open cloud storage. In 2021 **XXE was merged here**.

- **DBA picture:** default `SCOTT/TIGER`, `PUBLIC` grants on powerful packages, listener without a password on old versions.
- **Example:** the lab's `misconfig_scan` finds debug endpoint, directory listing, default admin password, stack traces, missing headers and weak cookie flags.
- **Defenses:** hardened, repeatable configuration (IaC, [DevSecOps ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md)); separate settings per environment; remove unused features; automated config checks in CI.

## 7. Vulnerable and outdated components (A06:2021)

Libraries, frameworks, runtimes or OS packages with known vulnerabilities, or no longer supported. Log4Shell (2021) is the textbook case.

- **DBA picture:** running a database version out of Premier Support with unapplied quarterly patches.
- **Defenses:** inventory (SBOM), SCA in the pipeline, patch policy with SLAs, remove unused dependencies, watch end-of-life dates. See [DevSecOps ch04](../../devsecops-course/04-software-component-analysis/README.md) and the repo's vulnerability management chapter. In 2025 this grows into **Software Supply Chain Failures**.

## 8. Identification and authentication failures (A07:2021)

Weak login and session handling: credential stuffing allowed (no rate limit), weak or default passwords, plaintext or weakly hashed passwords, session ids in URLs, sessions not invalidated at logout, missing or weak MFA.

- **Defenses:** MFA (passkeys/WebAuthn preferred), rate limiting and breached-password checks, NIST SP 800-63B guidance (length over complexity, no forced rotation; verify the current revision), new session id at login, server-side logout, secure cookie flags. Chapter 10 covers API authentication.

## 9. Software and data integrity failures (A08:2021)

Code or data trusted without checking integrity: auto-updates without signatures, CI/CD pipelines that anyone can modify, insecure deserialization of untrusted data, libraries pulled from untrusted CDNs without Subresource Integrity.

- **Defenses:** sign and verify artifacts (Sigstore/cosign), protect the pipeline, pin and verify dependencies, never deserialize untrusted data with native formats (pickle, Java serialization); use JSON with a schema. Chapter 12 has a safe pickle-canary lab.

## 10. Security logging and monitoring failures (A09:2021)

Attacks are not detected because events are not logged, logs are not monitored, or alerts go nowhere. The average time to detect a breach is long; good logs shorten it.

- **DBA picture:** auditing switched off, or audit trail written but never reviewed.
- **Defenses:** log logins, failures, access-control denials and high-value transactions with user, time and source; never log secrets or tokens; protect logs from tampering and CRLF injection; send them to a SIEM with alerts (see the repo's [SIEM chapter](../../cybersecurity-track/06-siem-sentinel-splunk/README.md)); test that alerts fire. In 2025 the category name stresses **alerting**.

## 11. Server side request forgery (A10:2021)

The server fetches a URL chosen by the attacker. Attackers use it to reach internal services (`http://localhost/admin`), cloud metadata endpoints (`169.254.169.254`, which can return temporary cloud credentials), or to scan the internal network.

- **Example:** `/stock?url=` in the [lab](labs/vulnerable-shop/README.md) returns a FAKE metadata canary.
- **Defenses:** allowlist exact hosts on the **parsed** URL (not a string prefix, which `https://good@evil/` bypasses); allow only `https`; block private, loopback and link-local ranges after DNS resolution; disable redirects or re-check each hop; network egress rules; on AWS require IMDSv2. In 2025 SSRF is folded into Broken Access Control.

## 12. 2021 to 2025 mapping

| 2021 (course) | 2025 (current; verify names at owasp.org/Top10) |
|---|---|
| A01 Broken Access Control | **A01 Broken Access Control** (now includes SSRF) |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection (includes XSS) | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | **A02 Security Misconfiguration** |
| A06 Vulnerable and Outdated Components | **A03 Software Supply Chain Failures** (broader: build systems, distribution, dependencies) |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery | merged into A01 |
| (new) | **A10 Mishandling of Exceptional Conditions** (error handling, failing open, unhandled edge cases) |

For APIs there is a separate **OWASP API Security Top 10 (2023)**, covered in chapter 13.

## 13. Scenario: one pentest report, mapped

A pentest of a food delivery app reports: (1) any courier can see any customer's address by changing an id; (2) the admin panel shows a full stack trace with the database host; (3) a library with a known RCE is in use; (4) the restaurant logo upload fetches a URL server-side and can reach `http://169.254.169.254/`; (5) 2,000 failed logins for one account in an hour triggered no alert. The champion maps them for the team: (1) A01, (2) A05, (3) A06, (4) A10 (A01 in 2025), (5) A09 and A07. The mapping helps the team see that three of five findings are missing **server-side checks**, which becomes the theme of the next sprint.

## 14. Checklist

- [ ] I can list the 2021 Top 10 in order with one example each.
- [ ] I can say what moved where in the 2025 list.
- [ ] I can explain bind variables as the fix for SQL injection.
- [ ] I can explain why a string-prefix allowlist does not stop SSRF.
- [ ] I can name one defense per category.
