# Lab: OpenAPI spec to API scan (BOLA, injection, missing auth)

**Course exercise:** "Using Swagger (OpenAPI) and ZAP to scan APIs iteratively". **Lesson:** [04 QA automation and OpenAPI](../../04-qa-automation-and-openapi-scans.md#4-openapi-swagger--zap-for-apis).

**Time:** 60 minutes. **Tests:** 7, offline. **Safety:** the mock API binds to **127.0.0.1** (ephemeral port) and is started and stopped by the tests. The scanner refuses non-loopback targets. Credentials are FAKE.

## Files

| File | Role |
|---|---|
| `fixtures/openapi.yaml` | OpenAPI 3.0: `POST /api/v1/login`, `GET /api/v1/products?search=` (secured), `GET /api/v1/orders/{orderId}` (secured) |
| `mockapi.py` | local REST API, weak and fixed. Weak: no auth on `/products` although the spec says secured, SQL built from `search` (error leaks), no ownership check on orders. Fixed: all three repaired |
| `apiscan.py` | `load_spec`, `endpoints`, `generate_requests`, `scan` |

## How it works

```text
spec -> endpoints(method, path, params, secured) -> requests per endpoint:
   baseline   with a valid token           (5xx = server error)
   no-auth    same call, no token          (200 = missing authentication)
   inject     ' and ' OR '1'='1 in string query parameters   (DB error text = SQL injection)
   bola       alice asks for an object owned by bob          (200 = BOLA)
```

The scanner is told which object id belongs to another user (`{"orderId": 2}`). That is test data you must prepare: object-level access control cannot be inferred from the spec alone.

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/openapi-zap-api-scan -v
```

## Expected output (real run, abridged)

```text
operations found in the spec:
  POST  /api/v1/login              secured=False params=[]
  GET   /api/v1/products           secured=True params=['search']
        test: baseline / no-auth / inject:search=' / inject:search=' OR '1'='1
  GET   /api/v1/orders/{orderId}   secured=True params=['orderId']
        test: baseline / no-auth / bola:orderId

== WEAK API: 3 finding(s), 7 requests ==
  [High  ] API-AUTH-MISSING  GET /api/v1/products       spec says secured, but anonymous call returned 200
  [High  ] API-BOLA          GET /api/v1/orders/{orderId} alice read object 2 owned by someone else
  [High  ] API-SQLI-ERROR    GET /api/v1/products       inject:search=' -> database error text

== FIXED API: 0 finding(s), 7 requests ==
```

## Steps

1. Read the spec, then the generated test list. Which parameter types get which tests?
2. In `mockapi.py` fix only the missing auth. Which finding disappears?
3. Add a `DELETE /api/v1/orders/{orderId}` operation to the spec. What would a safe scanner do with it? (Skip it or run it only on disposable test data.)
4. Change the BOLA input to an order alice owns (`{"orderId": 1}`). The scan flags BOLA anyway. Why? (The scanner trusts your claim about ownership: wrong test data gives a false positive.)
5. Swap in a Swagger 2.0 file. The loader refuses it: why might a scanner need a converter?

## Run the real tool

```text
docker run --rm -v "$(pwd)":/zap/wrk:rw -t ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py -t openapi.yaml -f openapi -r api.html
```

Verify the image and options at zaproxy.org. See [ZAP Docker scans](../../real-tools/zap-docker-scans.md).
