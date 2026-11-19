# Lab: Read an OpenAPI spec and find shadow and zombie endpoints

**Course items:** "Understanding APIs Using OpenAPI Specifications", "OpenAPI (Swagger)", "Performing Reconnaissance on an API". **Lesson:** [03 OpenAPI, Burp and reconnaissance](../../03-openapi-burp-and-reconnaissance.md#2-understanding-apis-using-openapi-specifications).

**Time:** 45 minutes. **Tests:** 8, offline. **Safety:** a JSON spec fixture and a hand-written "live inventory"; nothing is requested. Only test systems you own or have written permission to test.

## Goal

Extract what a tester needs from a spec (endpoints, effective security, auth schemes, versions), then compare it with what is actually served.

## Files

| File | Role |
|---|---|
| [fixtures/openapi.json](fixtures/openapi.json) | OpenAPI 3.1 spec: login and products public (`security: []`), orders and admin secured by `bearerAuth` |
| [openapi_recon.py](openapi_recon.py) | `load_spec`, `auth_schemes`, `endpoints`, `unauthenticated_endpoints`, `versioned_paths`, `recon`, `report` |
| [demo.py](demo.py) | prints the recon report |
| [test_aps_ch09_openapi_recon.py](test_aps_ch09_openapi_recon.py) | the tests |

The spec is JSON (valid OpenAPI) so no YAML library is needed. In the "live inventory" (what crawling and discovery found), `/api/v1/orders/{orderId}` is gone and `/api/v1/debug/env` is live but undocumented.

## Run

```text
.venv/Scripts/python appsec-course/09-api-tooling-and-reconnaissance/labs/openapi-recon/demo.py
.venv/Scripts/python -m pytest appsec-course/09-api-tooling-and-reconnaissance/labs/openapi-recon -q
```

## Real output

```text
# API recon report

auth schemes: {'bearerAuth': 'http/bearer', 'apiKey': 'apiKey'}
versions in spec: ['v1']

## Endpoints (spec)
  POST   /api/v1/login                  PUBLIC []
  GET    /api/v1/products               PUBLIC []
  GET    /api/v1/orders/{orderId}       secured ['bearerAuth']
  GET    /api/v1/admin/users            secured ['bearerAuth']

## Shadow (served, undocumented): [('GET', '/api/v1/debug/env')]
## Zombie (documented, gone):     [('GET', '/api/v1/orders/{orderId}')]
```

## Steps

1. Explain why `/api/v1/orders/{orderId}` is "secured" although the operation has no `security` key (it inherits the top-level `security`).
2. The `apiKey` scheme is declared but no operation uses it. Is that a finding? (Possibly a leftover; ask the team, and check whether the server still accepts keys.)
3. Add `"deprecated": true` to an operation and extend `endpoints` to report it.
4. Add a `servers` list with a staging URL; extend the report to print servers (staging hosts are often in scope by mistake or out of scope by contract: check).
5. Convert the spec to Swagger 2.0 shape and confirm `load_spec` refuses it. Real tools need a converter or a different importer.

## Run the real tool (hedged)

```bash
curl -s https://api.lab/openapi.json | jq '.paths | keys'                         # list paths
curl -s https://api.lab/openapi.json | jq '[.paths[][] | select(.security==[])]'  # public operations
npx @redocly/cli lint openapi.yaml       # lint a spec (Node tool; verify)
```

Import the spec into Burp (Professional), ZAP (OpenAPI add-on) or Postman. The repo's [devsecops OpenAPI + ZAP lab](../../../../devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/README.md) turns a spec into scan requests; this lab stops at recon so the two do not overlap.

## What you learned

- `security: []` marks a public operation; the top-level `security` is the default.
- A spec is a map of the intended API; recon finds the difference between intended and real.
- Shadow endpoints (live, undocumented) and zombie endpoints (old, should be gone) are OWASP API9:2023 Improper Inventory Management.
