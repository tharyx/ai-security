# MCP Penetration Test Report: Template

Copy this file, replace the angle-bracket text, delete what you do not need.

---

## 0. Document control

| | |
|---|---|
| Client / system | `<name>` |
| Test window | `<dates, time zone>` |
| Tester(s) | `<names>` |
| Report version / date | `<v1.0, date>` |
| Classification | `<confidential>` |
| Authorization reference | `<contract / letter id>` |

## 1. Executive summary (one page)

- **Overall risk:** `<Critical | High | Medium | Low>`, in one sentence why.
- **What we tested:** `<one sentence>`.
- **Top three issues** (plain language, business impact):
  1. `<e.g. Any authenticated user can read other tenants' notes through the search tool.>`
  2. `<...>`
  3. `<...>`
- **What to do first:** `<three actions, in order>`.
- **What went well:** `<e.g. descriptions are pinned; gateway blocked three of five injection tests.>`

## 2. Scope and method

- **In scope:** `<servers, versions, URLs, hosts/clients, gateways, pipelines>`
- **Out of scope:** `<...>`
- **Access level:** `<black / grey / white box>` **Accounts used:** `<roles>`
- **Model(s) and versions:** `<model, version, system prompt known?>`
- **Method:** `<scoping, recon, exploitation and chaining, impact, reporting>`; standards used: `<OWASP MCP Top 10, CWE, CVSS version>`.
- **Limitations:** `<time, no production, model non-determinism, third-party SaaS excluded>`

## 3. Attack surface summary

| Component | Transport | Auth | Tools / resources | Notes |
|---|---|---|---|---|
| `<notes-mcp>` | `<Streamable HTTP>` | `<OAuth 2.1>` | `<6 tools, 2 resources>` | `<shadow server found: no>` |

## 4. Findings summary

| ID | Title | Severity | OWASP MCP | CWE | Status |
|---|---|---|---|---|---|
| F-01 | `<Path traversal in read_note>` | High | MCP05 | CWE-22 | Open |
| F-02 | `<Verbose errors leak server paths>` | Medium | MCP08 | CWE-209 | Open |
| C-01 | `<Chain: injection -> broad DB role -> exfiltration>` | Critical | MCP06, MCP02, MCP10 | n/a | Open |

## 5. Detailed findings

### F-01 `<Title that states the impact>`

| | |
|---|---|
| Severity | `<High>` (CVSS `<v3.1 vector and score>`; agentic factors: `<requires the agent to read attacker text? yes/no>`) |
| Affected | `<server, tool, version, file:line if white box>` |
| References | OWASP MCP Top 10 `<MCP05>`, CWE-`<22>` |
| Likelihood / impact | `<explain in two sentences>` |

**Description.** `<What is wrong and why it matters, in plain language.>`

**Steps to reproduce.**
1. `<Connect as the low-privilege test user.>`
2. `<Call tools/call read_note with {"name": "../secret.txt"}.>`
3. `<Observe the canary CANARY-xxxx in the response.>`

**Evidence.** `<Redacted request/response, screenshot, log excerpt, canary value. Model/version and success rate if agent behavior is involved.>`

**Impact.** `<What an attacker gains: data classes, actions, tenants.>`

**Recommendation.**
1. `<Short term: canonicalize and check the path stays inside the notes directory.>`
2. `<Long term: add the abuse case as a regression test; add SAST rule; reduce the tool's file scope.>`

**Verification.** `<How we will know it is fixed: the fuzz test no longer returns the canary.>`

### C-01 `<Chain title>`

Narrative of the chain as numbered steps, each linked to the finding that enables it, then the combined impact and a single recommended "cut point" (the cheapest step to break).

## 6. Positive observations

`<Controls that worked and should be kept.>`

## 7. Residual risk and recommendations roadmap

| Priority | Action | Owner | Effort | Findings addressed |
|---|---|---|---|---|
| 1 (this week) | `<...>` | `<team>` | `<S/M/L>` | F-01, C-01 |

## 8. Retest

| ID | Retest date | Result (Fixed / Partially / Not fixed) | Notes |
|---|---|---|---|

## Appendix A. Tools and versions

`<scanner, fuzzer, client, model; versions; commands>`

## Appendix B. Raw data

`<Tool catalogue dump, fuzz corpus, request logs: with secrets removed.>`
