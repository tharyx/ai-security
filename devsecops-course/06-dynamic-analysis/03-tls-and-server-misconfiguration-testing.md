# Lesson 03: SSL/TLS and server misconfiguration testing

> **Sources merged:** [CDP 6] SSL misconfiguration testing; Server Misconfiguration Testing like secret folders and files.
> **Time:** about 2 hours. **Labs:** [tls-misconfiguration-checks](labs/tls-misconfiguration-checks/README.md), and the exposed-file checks in [dast-local-app](labs/dast-local-app/README.md).

## 1. "SSL" testing is really TLS testing

The syllabus says "SSL". SSL is the old name; **SSL 2.0 and 3.0 are broken and dead**, and **TLS 1.0 and 1.1 are deprecated** (RFC 8996, 2021). Today you want **TLS 1.2 and TLS 1.3**. We keep the word "SSL" because tools and people still use it ("SSL Labs", "SSL certificate").

DBA analogy: this is like the Oracle Net `SQLNET.ENCRYPTION` and `SSL_VERSION` settings. If you allow old versions or weak ciphers, a downgrade attack can force the weak one.

## 2. What a TLS test checks

| Area | Bad | Good |
|---|---|---|
| **Protocol versions** | SSLv2, SSLv3, TLS 1.0, TLS 1.1 enabled | only TLS 1.2 and 1.3 |
| **Cipher suites** | NULL, EXPORT, anonymous (anon), RC4, DES/3DES, MD5; CBC suites (legacy) | AEAD suites: AES-GCM, ChaCha20-Poly1305 |
| **Forward secrecy** | static RSA key exchange (`TLS_RSA_WITH_...`) | ECDHE or DHE key exchange (all TLS 1.3 suites) |
| **Certificate validity** | expired, not yet valid, expiring in under 30 days | valid, renewed by automation |
| **Trust** | self-signed or unknown CA, incomplete chain | issued by a trusted CA, full chain served |
| **Hostname** | name not in the SAN list | name matches a SAN (a wildcard covers one label only) |
| **Key and signature** | RSA under 2048 bits; SHA-1 or MD5 signature | RSA 2048+ or ECDSA P-256+; SHA-256+ |
| **HSTS header** | missing or short `max-age` | `Strict-Transport-Security` with a long `max-age` |

Other known classics your scanner may name: Heartbleed (OpenSSL bug), POODLE (SSLv3 padding), BEAST, CRIME/BREACH (compression), ROBOT, renegotiation flaws. They matter mostly when the old protocol or library is still present.

## 3. Tools

- **testssl.sh**: a shell script that tests protocols, ciphers, known attacks and the certificate. Good in CI with JSON output.
- **sslyze**: Python library and CLI, scriptable.
- **nmap** `--script ssl-enum-ciphers,ssl-cert`.
- **openssl s_client**: manual checks, e.g. `openssl s_client -connect host:443 -tls1` to see if TLS 1.0 is accepted.
- **SSL Labs**: hosted grading service for public sites.
- ZAP and Burp also report some TLS and header issues passively (HSTS, mixed content, cookie `Secure` flag).

All of them need **network access**, so the lab does not run them. Instead it analyses a **fixture** (the data such a tool would give you) with [`tlscheck.py`](labs/tls-misconfiguration-checks/tlscheck.py). That separates the *decision logic* (which protocol or cipher is a problem) from the *probing*, and makes it unit-testable.

## 4. In the pipeline

- Run the TLS check against **staging** on a schedule (weekly) and after changes to the load balancer or ingress.
- Fail the build on: old protocol, weak or anonymous cipher, expired certificate, hostname mismatch.
- Warn on: expiry within 30 days, CBC suites, missing TLS 1.3.
- Better: **monitor certificate expiry continuously** (many incidents are simply an expired cert). Use automated renewal (ACME) where you can.
- Remember where TLS ends: a load balancer or ingress often terminates TLS. Test the **public** endpoint, and also check that traffic behind it is protected if your policy requires it.

## 5. Server misconfiguration testing

The other half of this lesson: **things the web server should not serve**. Attackers look for these with simple wordlists ("forced browsing"). A DAST scanner does the same.

| What | Example path | Why it hurts |
|---|---|---|
| Version control folder | `/.git/HEAD`, `/.git/config` | the whole source and history can be downloaded |
| Environment/config files | `/.env`, `/config.php.bak`, `/web.config` | passwords and API keys |
| Backups and dumps | `/backup.sql`, `/db.zip`, `/site.tar.gz` | full data |
| Admin and debug paths | `/admin/`, `/phpmyadmin/`, `/actuator/env`, `/debug` | direct control or secrets |
| Directory listing | `/files/` showing "Index of" | file discovery |
| Default pages and sample apps | default Tomcat or IIS pages | known flaws |
| Verbose errors and banners | stack traces, `Server: Apache/2.4.x` | help the attacker |
| Dangerous HTTP methods | `TRACE`, `PUT`, `DELETE` open | tampering |
| Missing security headers | no CSP, `X-Content-Type-Options`, `X-Frame-Options` | weaker browser protection |

How the check works: request a known path list, and treat a **200 with the expected content** as a finding (checking the **content**, not only the status, avoids false positives from "soft 404" pages). The lab prober does this for `/.git/HEAD` (looks for `ref:`) and `/.env` (looks for `PASSWORD`).

Fixes:

- **Do not deploy** the `.git` folder, `.env` or backups into the web root. Build artifacts only (a multi-stage Docker image helps).
- Deny dotfiles and backup extensions at the web server or ingress.
- Turn off directory listing and server tokens.
- Return generic error pages; log details server-side.
- Keep secrets in a secret manager ([chapter 13](../13-secrets-management/README.md)), not in files next to the code.
- Add the security headers in one place (reverse proxy or middleware).

Related: the **fixed app** in the lab returns 404 for those paths and sets the headers, and the prober then reports zero findings.

## 6. Summary

- "SSL testing" means checking protocol versions, ciphers, certificate, hostname, key strength and HSTS.
- Test with testssl.sh or sslyze in CI against staging; fail on old protocols and weak ciphers; watch expiry.
- Server misconfiguration: hunt for `.git`, `.env`, backups, admin paths, listings and verbose errors.
- Fix at the source: do not ship these files; deny them at the edge; use a secret manager.

Existing material: [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) (headers and `/.git/HEAD`), [pentesting recon and scanning](../../cybersecurity-track/09-pentesting-fundamentals/02-recon-and-scanning.md).
