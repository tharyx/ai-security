# Lab: Abusing CORS misconfigurations

**Course topic:** "Abusing CORS Misconfigurations". Lesson: [03 section 3](../../03-post-exploitation-xss-and-cors.md#3-abusing-cors-misconfigurations). CORS as a security header is revisited in [chapter 14](../../../14-api-defenses-data-security-and-headers/README.md).

**Time:** 30 minutes. **Tests:** 11, all offline. **Safety:** a simulated browser applies the CORS read rules; the API key is FAKE. Only test systems you own or have written permission to test.

## Goal

Find the four classic CORS mistakes (origin reflection, `null`, suffix match, prefix match), see that a script on the attacker's site can read the victim's private API response, and fix it with an exact allowlist.

## Concept

The same-origin policy stops `evil.example` JavaScript from **reading** responses from `bank.example`. CORS lets a server relax that. If the server answers `Access-Control-Allow-Origin: <attacker origin>` with `Access-Control-Allow-Credentials: true`, the browser sends the victim's cookies **and** lets the attacker's script read the response.

- `*` cannot be used with credentials (browsers refuse), so developers "fix" it by reflecting the Origin: the classic bug.
- `null` is sent by sandboxed iframes and `file:` pages, which an attacker can create.
- `endswith("bank.example")` matches `evilbank.example`; `startswith("https://bank.example")` matches `https://bank.example.evil.net`.
- Always send `Vary: Origin` when the response depends on Origin (caches).
- **CORS is not CSRF protection:** simple requests (form POSTs) reach the server anyway; CORS only controls reading.
- Cookie `SameSite=Lax` (the Chromium default) blocks most cross-site credentialed `fetch` calls; the lab assumes `SameSite=None`, which APIs used by other sites often set.

## Steps

1. Run the demo and read the matrix.
2. Write a regex-based allowlist that is correct (`^https://([a-z0-9-]+\.)?bank\.example$`) and add tests for the four attacker origins.
3. Explain why reflecting Origin **without** credentials is much less severe.

## Run

```text
.venv/Scripts/python appsec-course/13-owasp-api-top-10-and-other-threats/labs/cors-misconfiguration/demo.py
.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats/labs/cors-misconfiguration -q -p no:cacheprovider
```

## Expected output (real run)

```text
Can a script on the attacker origin read alice's account with her cookie?
policy   https://evil.example           null                           https://evilbank.example       https://bank.example.evil.net  
reflect  READS balance + key            READS balance + key            READS balance + key            READS balance + key            
null     blocked                        READS balance + key            blocked                        blocked                        
suffix   blocked                        blocked                        READS balance + key            blocked                        
prefix   blocked                        blocked                        blocked                        READS balance + key            
wildcard blocked                        blocked                        blocked                        blocked                        
secure   blocked                        blocked                        blocked                        blocked                        

legit https://app.bank.example, secure policy: {'user': 'alice', 'balance': 250000, 'api_key': 'FAKE-key-0000'}
CORS is not CSRF protection: a form POST reaches the server without preflight? True
```

## Run the real tool (hedged)

In Burp Repeater, add `Origin: https://evil.example`, then `Origin: null`, then look-alike domains, and check the response headers. **Corsy** automates these checks (check maintenance). PortSwigger Web Security Academy has free CORS labs.

## What you learned

- Use an exact allowlist; never reflect arbitrary origins with credentials.
- CORS only governs reading responses; it does not stop requests from being sent.
