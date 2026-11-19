# Learner worksheet: documenting STRIDE findings (copy and fill)

System: `<name>` · Reviewer: `<name>` · Date: `<date>` · Tool output: `stride_mcp.py` run on `<commit or file hash>`

| ID | Element / flow | STRIDE | Threat | Decision (confirm / false positive / accept / re-scope) | Reason | Existing control | Missing control | Owner | Test or evidence that proves the fix |
|---|---|---|---|---|---|---|---|---|---|
| FND-003 | host | T | Poisoned tool description or schema steers the model | confirm | Host shows only names to the user today | none | description_scanning, tool_pinning | `<name>` | `defend-tool-poisoning` tests; a poisoned fixture is blocked |
| FND-047 | F8 host to db server | T | No TLS on loopback HTTP | accept | Loopback only, bearer token required, owner signs for 12 months | bearer_auth | tls | `<name>` | Port is bound to 127.0.0.1; see the transport-security lab in chapter 4 |
| | | | | | | | | | |

## Threats I added that the library did not have

| ID | Element / flow | STRIDE | Scenario | OWASP MCP / ASI | Why the library missed it |
|---|---|---|---|---|---|
| | | | | | |

## Notes

* Assumptions:
* Open questions for the architect:
* Findings I could not rate:
