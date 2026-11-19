# Lesson 05: Attacks on the Application Side

> **Chapter:** 2 · Attacking Code and Application Supply Chain · **Time:** ~4 hours
> **You will:** explain injection, cross-site scripting (XSS) and server-side request forgery (SSRF), show how they connect to the supply chain, and find and fix them with the SAST and DAST labs.

| | |
|---|---|
| **Prerequisites** | Basic web knowledge (HTTP, HTML, SQL) |
| **Labs** | [sast](labs/sast/README.md) · [dynamic-analysis](labs/dynamic-analysis/README.md) |
| **Related** | [pentest lesson: web app testing](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md) · [pentest lesson: exploitation concepts](../../cybersecurity-track/09-pentesting-fundamentals/04-exploitation-and-privilege-escalation-concepts.md) · [SQLi vs parameterized, reflected XSS mini-app](../../cybersecurity-track/09-pentesting-fundamentals/lab/mini_app.py) · [cloud security](../../cybersecurity-track/10-cloud-security/README.md) |
| **Syllabus lines** | Attacks on Application Side · Injection attacks · Cross Site Scripting (XSS) · Server Side Request Forgery |
| **Maps to** | OWASP Top 10 (A03 Injection, A10 SSRF in the 2021 list; verify the newest edition) · CWE-89, CWE-79, CWE-918 |

> **Safety.** The labs run a deliberately vulnerable app on `127.0.0.1` only; secrets are FAKE. Test only what you own or have written permission to test.

## Why this matters

- Application bugs are the last link: even a perfect supply chain delivers a vulnerable app if the code is flawed.
- The supply chain **brings app-side bugs in**: a vulnerable library (Log4Shell, CVE-2021-44228, a log-injection flaw in a ubiquitous Java library, December 2021) is an injection bug you did not write. A hijacked third-party script (polyfill.io, Magecart) is **XSS by supply chain**: attacker code runs in your page.
- SSRF turns your server into the attacker's proxy to internal systems and cloud metadata. The 2019 Capital One breach is the standard case: an SSRF reached a cloud metadata service, and an over-privileged role did the rest (hedge details; verify).

## 1. Injection attacks

**Root cause:** untrusted data is mixed into a command or query that an interpreter parses, so the data becomes code. One idea, many interpreters:

| Type | Sink | Example shape (harmless) |
|---|---|---|
| **SQL injection** | database query | `... WHERE id = ` + user input; input `1 OR 1=1` |
| **OS command injection** | `os.system`, `shell=True` | `ping ` + host; host contains `; id` |
| **Template injection (SSTI)** | template engine | user text rendered as a template |
| **NoSQL, LDAP, XPath injection** | query languages | operators inside JSON or filters |
| **Expression and log injection** | expression languages, logging libraries | Log4Shell: log text that triggered a lookup |
| **Deserialization** | `pickle.loads`, Java serialization | untrusted bytes become objects with side effects |
| **Header and CRLF injection** | HTTP headers | newline in a header value |
| **Argument injection** | command arguments | a value that starts with `-` becomes an option |

**Defend (root-cause fixes first):**

1. **Separate code from data.** Parameterized queries and prepared statements; argument lists (not shell strings); safe loaders (`yaml.safe_load`, JSON instead of pickle).
2. **Validate with allowlists** (types, ranges, formats) as defense in depth. Do not rely on blocklists.
3. **Least privilege.** The database user cannot `DROP`; the process cannot reach the internet.
4. Hide detailed errors (the lab's SQL error message is what an error-based scanner uses).
5. Keep libraries patched (SCA) because injection bugs also live in dependencies.

```python
# vulnerable                                       # fixed
cur.execute("... WHERE id = " + uid)               cur.execute("... WHERE id = ?", (int(uid),))
os.system("ping " + host)                          subprocess.run(["ping", "-c", "1", host])
```

**Where to practise:** the [pentest mini-app lab](../../cybersecurity-track/09-pentesting-fundamentals/lab/mini_app.py) (SQLi versus parameterized) and this chapter's [SAST](labs/sast/README.md) and [DAST](labs/dynamic-analysis/README.md) labs.

## 2. Cross Site Scripting (XSS)

**Root cause:** untrusted data is placed into a web page without the right **output encoding**, so the browser treats it as HTML or script.

| Type | Where the payload lives |
|---|---|
| **Reflected** | in the request (a link), echoed in the response |
| **Stored** | saved by the server (comment, profile) and shown to others |
| **DOM-based** | client-side JavaScript writes untrusted data into the page (`innerHTML`, `document.write`) |

**Impact:** the script runs as the victim on your site: it can read the page, call APIs with the victim's session, change content (fake login forms), and steal tokens that are readable by JavaScript.

**Supply-chain angle:** a third-party script is XSS you chose to include. Defend with SRI, self-hosting, and CSP ([lesson 03](03-supply-chain-attacks-on-package-managers.md)).

**Defend (layers):**

| Layer | Control | Type |
|---|---|---|
| Output encoding for the right context (HTML body, attribute, JS, URL) using the framework's auto-escaping | `html.escape`, template auto-escape, no `innerHTML` for untrusted text | Hard |
| Safe frameworks and APIs | avoid raw-HTML features (`Markup`, `dangerouslySetInnerHTML`) with user data | Hard |
| **CSP** (strict, nonce-based) | blocks injected inline script even if encoding is missed | Hard (second line) |
| Cookie flags | `HttpOnly`, `Secure`, `SameSite` limit what script can steal | Hard |
| Sanitize rich text with a maintained library | for HTML you must allow | Hard |
| Input validation | helps, never enough alone | Soft |

## 3. Server Side Request Forgery (SSRF)

**Root cause:** the server fetches a URL that the user controls (preview, import, webhook, image proxy, PDF generator) without restricting the destination. The attacker points it at places they cannot reach but the server can:

- **cloud metadata services** (for example the link-local address used by cloud instance metadata), which hold temporary credentials;
- internal admin panels, databases, Kubernetes APIs;
- `localhost` services.

**Bypass tricks to know (for defenders):** IP in decimal/octal/hex form, DNS names that resolve to internal IPs, redirects from an allowed host to an internal one, **DNS rebinding** (the name resolves to a public IP at check time and an internal IP at use time), URL-parser differences, and non-HTTP schemes (`file:`, `gopher:`) in some libraries.

**Defend (layers):**

| Layer | Control |
|---|---|
| Do not fetch user URLs if you can avoid it | choose from a server-side list |
| **Allowlist** of hosts (exact match, not `startswith`), schemes (https only) and ports | the [lab's fixed app](labs/dynamic-analysis/README.md) |
| Resolve the name, **check the resulting IP** (block private, loopback, link-local) and **connect to that IP**; do not follow redirects blindly | defeats rebinding when done right |
| Network egress controls for the app (the server cannot reach internal ranges) | Hard, independent of code |
| Cloud: enforce the hardened metadata service version (IMDSv2 on AWS), least-privilege roles | verify per cloud |
| Do not return raw responses to the user | limits data leaks |

## How the pieces connect

| Bug | Found by | Fixed by | Shown in |
|---|---|---|---|
| SQLi, command injection | SAST (pattern and taint), DAST (error and boolean probes) | parameters, arg lists | SAST lab rules 002, 005; DAST `/user` |
| XSS | SAST (raw HTML sinks), DAST (reflected marker) | output encoding, CSP | SAST 009; DAST `/search` |
| SSRF | SAST (tainted URL), DAST (internal canary) | allowlist, egress filter | SAST 011; DAST `/fetch` |
| Vulnerable library | SCA | upgrade, mitigate | [sca lab](labs/sca/README.md) |

## Hands-on

1. Run the [SAST lab](labs/sast/README.md) and map each finding to injection, XSS or SSRF.
2. Run the [DAST lab](labs/dynamic-analysis/README.md); compare the vulnerable and fixed app's output.
3. In the fixed app, change the SSRF allowlist to a prefix check and find the hostname that bypasses it.

## Real-world scenarios

1. **A "preview link" feature returns cloud credentials.** Cause: SSRF to the metadata service. Fix: allowlist, block link-local, IMDSv2, least-privilege role; rotate credentials.
2. **A search page pops an alert for a crafted link.** Reflected XSS. Fix: output encoding, CSP; check where else the same helper is used.
3. **A new CVE in a logging library affects your services.** An injection flaw in a dependency. Fix: SCA and SBOM to find affected services; patch; mitigate (disable the feature); monitor.

## Common mistakes

- Filtering "bad words" instead of parameterizing.
- Escaping on input instead of on output for the right context.
- SSRF allowlists with `startswith` or `contains`.
- Showing database errors to users.
- Thinking CSP replaces encoding.

## Interview preparation

<details><summary><b>Q1. What is the root cause of injection and the best fix?</b></summary>
Untrusted data is concatenated into an interpreter's command or query so it is parsed as code. The best fix keeps code and data separate: parameterized queries, argument lists, safe parsers, and least privilege as backup.
</details>

<details><summary><b>Q2. Reflected, stored and DOM XSS?</b></summary>
Reflected: the payload is in the request and echoed back. Stored: it is saved and shown to other users. DOM: client-side script writes untrusted data into the page. All are fixed by context-aware output encoding, with CSP as a second layer.
</details>

<details><summary><b>Q3. Why is SSRF dangerous in the cloud?</b></summary>
The server can reach the metadata service and internal systems, which return credentials and data that the attacker cannot reach directly. Allowlists, IP checks after resolution, egress filtering, hardened metadata (IMDSv2) and least-privilege roles limit the impact.
</details>

<details><summary><b>Q4. How can a supply-chain issue become an XSS or injection issue?</b></summary>
A hijacked third-party script runs in your page (XSS by supply chain), and a vulnerable library can contain injection flaws, as with Log4Shell. SRI, CSP, SCA and patching address these.
</details>

## Checklist (definition of done)

- [ ] I can fix SQLi, command injection and XSS in code and say why the fix works.
- [ ] I can list four SSRF bypass ideas and the layered defense.
- [ ] I ran both labs.

## References

- OWASP Top 10 and cheat sheets (SQL Injection Prevention, XSS Prevention, SSRF Prevention): <https://owasp.org/>, <https://cheatsheetseries.owasp.org/>
- PortSwigger Web Security Academy (free labs): <https://portswigger.net/web-security>
- CWE: <https://cwe.mitre.org/> (CWE-89, CWE-79, CWE-918)
- AWS documentation on IMDSv2: <https://docs.aws.amazon.com/>
