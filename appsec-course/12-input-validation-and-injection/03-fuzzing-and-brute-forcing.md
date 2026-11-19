# Lesson 03: Fuzzing APIs, and Brute Forcing Business Logic

**Syllabus items covered:** [CASP 5] "Fuzzing", "Fuzzing 101", "Fuzzing vs Brute Forcing", "Fuzzing APIs Using Open Source and Commercial Tools", "Burp Suite Intruder", "OWASP ZAP Fuzzer", "Wfuzz", "FFUF", "Getting Free Coupons Without Knowing Coupon Code".

**Time:** 75 minutes. **Labs:** [mini-fuzzer](labs/mini-fuzzer/README.md), [free-coupons](labs/free-coupons/README.md). Real tools: [real-tools/fuzzing-tools.md](real-tools/fuzzing-tools.md). Related: property-based fuzzing of MCP tools in [cmcpse-course ch5](../../cmcpse-course/ch5-devsecops-for-mcp-security/03-dast-fuzzing-and-runtime-testing.md), path discovery with ffuf in [chapter 09](../09-api-tooling-and-reconnaissance/README.md).

> Only test systems you own or have written permission to test. Fuzzing can crash services and fill databases: use a test environment.

## 1. Fuzzing 101

**Fuzzing** sends large numbers of unexpected, malformed or random inputs to a program and watches for **bad behaviour**. It finds the bugs nobody thought to write a test for.

Building blocks:

1. **Target and entry points:** each API parameter (path, query, header, JSON field, file).
2. **Input generation:**
   - *Mutation-based:* start from valid requests (a corpus) and flip, repeat, truncate, change types.
   - *Generation-based:* build inputs from a grammar or schema (OpenAPI, GraphQL schema).
   - *Coverage-guided:* the fuzzer watches code coverage and keeps inputs that reach new code (AFL++, libFuzzer, Atheris for Python). Mostly for libraries and parsers.
   - *Property-based:* Hypothesis-style generators plus invariants.
3. **Interesting values:** boundaries (0, -1, max int + 1), empty, very long, wrong types (`[]`, `{}`, `null`, `true`), special characters, format strings, injection probes, Unicode tricks, path traversal.
4. **Oracle:** what counts as a finding: 5xx, stack traces, timeouts, reflected unencoded input, schema violations in responses, business rules broken (negative totals), resource spikes.
5. **Triage:** deduplicate, minimise the failing input, reproduce with a fixed seed.

**Scenario.** A payments team fuzzed its refund API's JSON body from the OpenAPI schema in CI. On the first run, `"amount": 1e309` (parsed as infinity) produced a 500 with a stack trace naming the library version, and `"amount": -1` produced a refund **to** the customer for a negative charge. Both had passed unit tests written by the same developers who wrote the code.

## 2. Fuzzing vs brute forcing

| | Fuzzing | Brute forcing |
|---|---|---|
| Question | "What input breaks it?" | "Which candidate is right?" |
| Inputs | Malformed, unexpected | Valid-looking candidates from a wordlist or range |
| Oracle | Errors, crashes, anomalies | A different response for the right candidate |
| Examples | 500 on `qty="abc"` | `/api/v1/backup` exists; coupon `SAVE911`; password `letmein` |
| Defence | Validation, error handling, robust parsers | Rate limits, lockouts, large keyspaces, uniform responses |

Tools blur the line: ffuf, wfuzz, Burp Intruder and ZAP Fuzzer do both. The **mini-fuzzer** lab uses one engine for both modes so you can see the difference is the inputs and the oracle.

## 3. Business logic brute force: the free coupon case

"Getting free coupons without knowing the coupon code" combines a **small keyspace** (predictable codes), **no rate limit**, and **weak business rules** (coupons reusable and stackable, no minimum total). None of these is an injection; all of them are logic flaws that scanners rarely find. OWASP API 2023 calls this class **API6 Unrestricted Access to Sensitive Business Flows** (and API4 for missing limits).

Controls: long random codes; per-account, per-IP and global attempt limits with `429` and backoff; single use; one coupon per order; server-side price calculation and floors; alerts on unusual discount rates. CAPTCHA can add friction but is not a control on its own (see [chapter 10](../10-api-authentication/README.md)).

## 4. Fuzzing APIs using open source and commercial tools

| Tool | Licence | Strengths | Notes (verify) |
|---|---|---|---|
| **Burp Suite Intruder** | Commercial (Pro); throttled in Community | Payload positions, attack types (Sniper, Battering ram, Pitchfork, Cluster bomb), grep/extract, integrates with your proxy history | Pro or the course lab licence for full speed |
| **ZAP Fuzzer** (ZAP by Checkmarx) | Open source | GUI fuzzer add-on, payload generators and processors, scriptable; ZAP Automation Framework for CI | ZAP was renamed "ZAP by Checkmarx" in 2024 |
| **wfuzz** | Open source (Python) | `FUZZ` keyword anywhere, encoders, filters by code/lines/words/chars | Little maintenance in recent years |
| **ffuf** | Open source (Go) | Very fast, `FUZZ` keyword, many filters/matchers, JSON output | Actively maintained |
| **Schemathesis / RESTler** | Open source | Generate requests from OpenAPI; stateful sequences (RESTler) | Good for CI |
| **Commercial API DAST** | Commercial | Burp Suite DAST, others with OpenAPI import | Check features per vendor |

### 4.1 Burp Suite Intruder

Send a request from Proxy history to Intruder, mark positions with `§`, choose an attack type and payloads (lists, numbers, brute forcer, null payloads), add **Grep - Match** for error strings, run, and sort by status/length/time.

### 4.2 OWASP ZAP Fuzzer

Right-click a request in the History or Sites tree, choose **Fuzz...**, highlight the value, add payloads (strings, files, FuzzDB/other lists, regex generators, scripts) and optional processors (URL-encode, Base64), then start and filter results by state and size.

### 4.3 Wfuzz

`wfuzz -z file,wordlist.txt --hc 404 https://lab.example/api/v1/FUZZ` (hide 404s). Supports multiple payloads (`FUZZ`, `FUZ2Z`), encoders and body/header fuzzing.

### 4.4 FFUF

`ffuf -u https://lab.example/api/v1/FUZZ -w wordlist.txt -fc 404` for paths; `-X POST -d '{"qty":FUZZ}' -H "Content-Type: application/json" -w values.txt -mc 500` to fuzz a JSON field and match server errors.

Commands are hedged and detailed in [real-tools/fuzzing-tools.md](real-tools/fuzzing-tools.md).

## Check yourself

1. Why is the oracle the most important part of a fuzzer?
2. Name two things that turn a coupon brute force from feasible to infeasible.
3. When would you choose ffuf over Burp Intruder, and the other way round?
