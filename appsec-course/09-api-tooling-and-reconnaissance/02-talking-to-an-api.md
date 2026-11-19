# Lesson 02: Talking to an API: curl, Postman, OpenAPI, Python and a MITM Proxy

**Syllabus items covered:** "Ability To Talk to an API", "cURL (curl)", "Postman", "OpenAPI (Swagger)", "Python", "An MITM Proxy", "Understanding an API Language (Endpoints, Verbs, and State)", "Understanding cURL Command", "Performing CRUD Operations Using API" ([CASP 2]).

**Time:** 90 minutes. **Lab:** [toy-api-crud](labs/toy-api-crud/README.md). **Real tools:** [Burp Suite for APIs](real-tools/burp-suite-for-apis.md), [Postman and alternatives](real-tools/postman-and-alternatives.md).

> **DBA analogy.** curl is your `sqlplus -s`: quick, scriptable, exact. Postman is SQL Developer: a GUI with saved connections and worksheets. An OpenAPI spec is the data dictionary (`DBA_TAB_COLUMNS` for the API). A MITM proxy is a SQL trace (10046) you can also edit on the fly.

## 1. Ability to talk to an API

To test an API you must be able to send **exactly** the request you want, see **exactly** what comes back, and repeat it with small changes. Each tool does one part best:

| Tool | Best for | Weak at |
|---|---|---|
| **curl** | one precise request, scripts, sharing a reproducible command | long multi-step flows, visual comparison |
| **Postman** (or Bruno, Insomnia, HTTPie) | collections, environments, auth helpers, team sharing | security testing at scale; Postman needs a cloud login for most features |
| **OpenAPI spec** | knowing every endpoint, parameter and auth scheme | anything undocumented |
| **Python** (`requests`, `httpx`, `urllib`) | loops, two-user BOLA checks, custom logic, glue | quick one-offs |
| **MITM proxy** (Burp Suite, ZAP, mitmproxy) | seeing and editing real app traffic, replay, fuzzing | needs setup (proxy + CA certificate) |

## 2. cURL (curl)

curl is installed on Linux, macOS and Windows 10+ (`curl.exe`; in Windows PowerShell 5.1 the bare word `curl` is an alias for `Invoke-WebRequest`, so type `curl.exe`).

## 3. Understanding the cURL command

```bash
curl -s -X POST "https://api.lab/api/v1/items" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"widget"}' \
     -w '\nstatus=%{http_code}\n'
```

| Option | Meaning |
|---|---|
| `-X METHOD` | the HTTP method (default GET, or POST when `-d` is used) |
| `-H 'Name: value'` | add a header |
| `-d DATA` / `--data-raw` | request body |
| `--json DATA` | body plus JSON content-type and accept headers (curl 7.82+) |
| `-u user:pass` | HTTP Basic authentication |
| `-i` / `-v` | show response headers / show the whole exchange |
| `-s` / `-S` / `-f` | silent / still show errors / fail (exit 22) on HTTP >= 400 |
| `-o file` / `-w FORMAT` | write body to a file / print variables such as `%{http_code}` |
| `-k` | **skip TLS verification**: lab only, never in scripts against real systems |
| `-x http://127.0.0.1:8080` | send through a proxy (Burp/ZAP) |
| `-b` / `-c` | send / save cookies |

Browser developer tools (Network tab) and Burp both offer **"Copy as cURL"**: the fastest way to turn something the app did into a reproducible test. The lab's `parse_curl` and `build_curl` read and write such commands.

## 4. Postman

A GUI client with **collections** (saved requests), **environments** (variables such as `{{baseUrl}}` and `{{token}}`), auth helpers (Basic, Bearer, OAuth 2.0 flows), scripts, and a **runner**. It can import an OpenAPI spec to create a collection. Hedged notes for 2026: most features require signing in to a Postman cloud account and collections sync to Postman's cloud. Watch what you store there. Offline or open alternatives: **Bruno** (collections as files in Git), **Insomnia**, **HTTPie**. See [real-tools/postman-and-alternatives.md](real-tools/postman-and-alternatives.md).

## 5. OpenAPI (Swagger)

A machine-readable description of a REST API (YAML or JSON): servers, paths, methods, parameters, request/response schemas and **security schemes**. Versions: Swagger 2.0 (= OpenAPI 2), OpenAPI 3.0, **3.1** (aligned with JSON Schema), **3.2.0 published Sept 2025 (verify)**. Common places to find it: `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/swagger-ui/`, `/docs`, `/redoc`. Reading it is lesson 03 and the [openapi-recon lab](labs/openapi-recon/README.md). Spec-driven scanning is in [devsecops ch06](../../devsecops-course/06-dynamic-analysis/04-qa-automation-and-openapi-scans.md#4-openapi-swagger--zap-for-apis).

## 6. Python

For anything beyond a handful of requests, script it:

```python
import os, requests                        # pip package; urllib.request is the stdlib option
BASE = "https://api.lab"
alice = {"Authorization": f"Bearer {os.environ['ALICE_TOKEN']}"}
bob_order = 1002                           # an object owned by bob (test data you prepared)
r = requests.get(f"{BASE}/api/v1/orders/{bob_order}", headers=alice, timeout=10)
print(r.status_code)                       # 200 here = BOLA finding; expect 403/404
```

Python is the glue for two-user authorization tests, loops over IDs, custom token handling and parsing results. This course's labs use only the standard library (`urllib`, `json`, `http.server`).

## 7. An MITM proxy

A man-in-the-middle **testing** proxy sits between your client (browser, mobile app, Postman, curl) and the API. You point the client at the proxy and trust the proxy's CA certificate so it can decrypt HTTPS. Then you can:

- see every request the app makes, including ones the docs never mention;
- **intercept** and edit a request before it leaves (change an ID, add `"role":"admin"`);
- **replay** a request with changes (Burp Repeater);
- **automate** variations (Burp Intruder, ZAP Fuzzer);
- record a session for later analysis and reporting.

Tools: **Burp Suite** (Community free; Professional paid; Burp Suite DAST, formerly Enterprise, for CI), **ZAP by Checkmarx** (free, open source), **mitmproxy** (open source, scriptable in Python). Setup is in [real-tools/burp-suite-for-apis.md](real-tools/burp-suite-for-apis.md). Mobile apps may use certificate pinning, which needs extra lab-only steps covered by your course.

## 8. Understanding an API language: endpoints, verbs and state

| Concept | Meaning | Example |
|---|---|---|
| **Endpoint** | a URL for a resource or collection | `/api/v1/items` (collection), `/api/v1/items/7` (one item) |
| **Verb** | what you do to it | GET read, POST create, PUT replace, PATCH update, DELETE remove |
| **State** | the resource's data at a moment, changed by verbs | item 7 has `name: "widget"`; after PUT it has `name: "gadget"` |
| **Representation** | how state is sent | JSON body |
| **Status** | what happened | 201 Created + `Location`, 204 No Content after DELETE |

REST's idea: you transfer **representations of state** with standard verbs. A tester thinks in the same terms: "which verbs does this endpoint accept, and which state changes are allowed for **this** caller?" Unexpected verbs (`DELETE` on a resource the UI only reads) are a classic finding (BFLA, [chapter 11](../11-api-authorization-and-oauth/README.md)).

## 9. Performing CRUD operations using an API

| CRUD | Verb | curl | Typical success |
|---|---|---|---|
| Create | POST | `curl -X POST -d '{"name":"widget"}' $BASE/api/v1/items` | 201 + Location |
| Read | GET | `curl $BASE/api/v1/items/1` | 200 |
| Update | PUT / PATCH | `curl -X PUT -d '{"name":"gadget"}' $BASE/api/v1/items/1` | 200 or 204 |
| Delete | DELETE | `curl -X DELETE $BASE/api/v1/items/1` | 204 |
| List | GET | `curl $BASE/api/v1/items` | 200 + array |

Security questions for every CRUD endpoint: does Create accept fields it should not (`owner_id`, `price`, `isAdmin`)? Does Read check ownership? Can Update change someone else's item or a protected property? Is Delete restricted to the right role? Is List paginated with a maximum page size?

## 10. Scenario: "Copy as cURL" finds the bug

A tester opens a banking app's web front end, clicks "download statement", and in the browser's Network tab uses **Copy as cURL**. The command contains `?accountId=88123`. Re-running it with `accountId=88124` returns another customer's statement. The whole finding is two curl commands, which also become the regression test after the fix.

## 11. Self-check

1. Which curl options print only the status code, and which one is dangerous outside a lab?
2. Why must you install the proxy's CA certificate, and why only in a test browser profile?
3. Write the five CRUD calls for `/api/v1/notes` as curl commands.

Next: [Lesson 03, OpenAPI, Burp and reconnaissance](03-openapi-burp-and-reconnaissance.md).
