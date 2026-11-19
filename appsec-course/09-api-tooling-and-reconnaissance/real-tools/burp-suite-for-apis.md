# Real tools: setting up Burp Suite for API security testing (hedged)

**Course item:** "Setup the Burp Suite for API Security Testing" ([CASP 2]), also "An MITM Proxy". **Offline equivalents in this repo:** the [toy-api-crud lab](../labs/toy-api-crud/README.md) (requests as curl commands), [path-discovery-ffuf](../labs/path-discovery-ffuf/README.md) (Intruder-style variation), [user-enumeration](../labs/user-enumeration/README.md) (Comparer-style diffing). Burp concepts for web apps: [cybersecurity-track Burp workflow](../../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md#26-burp-suite-the-workflow-concepts).

> Only test systems you own or have written permission to test. Menu names change between Burp releases: **verify against the current PortSwigger documentation** and your course lab.

## Editions (Nov 2026, verify)

| Edition | Cost | Notes |
|---|---|---|
| Burp Suite Community | free | Proxy, Repeater, Decoder, Comparer, Intruder (throttled), no scanner, no project files |
| Burp Suite Professional | paid licence | scanner, unthrottled Intruder, API definition scanning, project files, extensions |
| Burp Suite DAST (formerly Enterprise) | paid | scheduled and CI scans |
| Dastardly | free | CI scanner from PortSwigger (web-focused) |

Free alternative: **ZAP by Checkmarx** (OpenAPI/GraphQL/SOAP import add-ons, Fuzzer, Automation Framework). Repo guide: [ZAP Automation Framework](../../../devsecops-course/06-dynamic-analysis/real-tools/zap-automation-framework.md).

## 1. Install and start

1. Download from PortSwigger (official site only). It bundles its own Java runtime.
2. Start a **temporary project** (Community) or a disk project (Professional). Use Burp defaults.
3. **Proxy → Proxy settings**: the listener should be `127.0.0.1:8080`. Do not bind to all interfaces.

## 2. Send traffic through Burp

| Client | How |
|---|---|
| Burp's browser | Proxy → Intercept → "Open browser" (pre-configured, no certificate step) |
| curl | `curl -x http://127.0.0.1:8080 -k https://api.lab/...` (`-k` only because Burp re-signs TLS; lab only) or `--cacert burp.pem` |
| Postman / Bruno / Insomnia | Settings → Proxy → `127.0.0.1:8080`; disable SSL verification **only** for the lab workspace or import the CA |
| Python | `requests.get(url, proxies={"https": "http://127.0.0.1:8080"}, verify="burp.pem")` |
| Mobile app | device Wi-Fi proxy to your host IP; install the CA in the test device; pinned apps need extra lab-specific steps from your course |

**CA certificate:** with Burp running, browse to `http://burpsuite` (through the proxy) to download it, or export it from Proxy settings. Install it in a **separate test browser profile**, never your daily browser, and remove it after the engagement.

## 3. Scope first

**Target → Scope settings:** add the in-scope host(s), for example `api.lab`. Then filter Proxy history to "Show only in-scope items" and enable "drop out-of-scope requests" if your version offers it. This keeps you inside your rules of engagement.

## 4. Load the API definition

- **Professional:** create a new scan from an API definition (OpenAPI JSON/YAML, recent versions also SOAP WSDL and Postman collections; verify), review the listed endpoints, configure authentication, then run a crawl-free audit.
- **Community:** use an extension from the BApp Store such as an OpenAPI parser (check which is maintained), or run the Postman collection through the proxy so every endpoint appears in history.
- Either way, also browse the real app so you capture **undocumented** calls; compare with the spec (lesson 03, shadow endpoints).

## 5. The core API workflow

1. **Proxy → HTTP history:** find the request. Right-click → **Send to Repeater**.
2. **Repeater:** change one thing at a time: the object ID, the method, a body field (`"role":"admin"`), remove the `Authorization` header, swap in another user's token. Note the status, length and body.
3. **Comparer:** send two responses (user A vs user B, existing vs missing account) to diff them. This is how you prove enumeration or BOLA.
4. **Intruder:** mark a position (an ID, a username) and load a small payload list. Sniper for one position, Pitchfork for paired lists. Throttle to the agreed rate. Community Intruder is deliberately slow.
5. **Decoder:** base64/URL decode tokens; **JWT extensions** (for example "JWT Editor", verify) to view and modify JWTs ([chapter 10](../../10-api-authentication/README.md)).
6. **Logger / Organizer** (newer versions): keep evidence for the report.

## 6. Authentication handling

- Bearer tokens: add them with a **session handling rule** or a "match and replace" rule so Repeater/Intruder always send a fresh token.
- Two users: keep two Repeater tabs, or use an authorization-testing extension (Autorize-style; verify the current name) that replays every request with the second user's token and highlights responses that still succeed.
- Never paste production tokens into shared project files.

## 7. Clean up

Remove the CA certificate from test profiles, delete project files containing tokens, and record the dates and scope of testing in your report.

## Exam pointers

- Know the difference between **Intercept** (pause and edit live) and **Repeater** (resend at will).
- BOLA proof = same request, two users, both 200, different owners.
- Community Intruder is throttled: for big lists, use ffuf or a Python script within scope.
