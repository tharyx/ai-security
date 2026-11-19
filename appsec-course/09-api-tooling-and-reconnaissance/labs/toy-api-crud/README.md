# Lab: Endpoints, verbs and state; curl commands; CRUD

**Course items:** "Understanding an API Language (Endpoints, Verbs, and State)", "Understanding cURL Command", "Performing CRUD Operations Using API", "cURL (curl)". **Lesson:** [02 Talking to an API](../../02-talking-to-an-api.md).

**Time:** 45 minutes. **Tests:** 8, offline. **Safety:** the API is a Python function over an in-memory dict; curl commands are **parsed**, never executed. Only test systems you own or have written permission to test.

## Goal

Map each HTTP verb to a state change, read and write curl commands precisely, and run a full Create-Read-Update-Delete cycle.

## Files

| File | Role |
|---|---|
| [toyapi.py](toyapi.py) | `ToyApi.handle(method, path, headers, body)` for `/api/v1/items[/id]`; `parse_curl`, `build_curl`, `call_with_curl` |
| [demo.py](demo.py) | drives a CRUD cycle with six curl commands |
| [test_aps_ch09_toy_api_crud.py](test_aps_ch09_toy_api_crud.py) | the tests |

## Run

```text
.venv/Scripts/python appsec-course/09-api-tooling-and-reconnaissance/labs/toy-api-crud/demo.py
.venv/Scripts/python -m pytest appsec-course/09-api-tooling-and-reconnaissance/labs/toy-api-crud -q
```

## Real output

```text
=== Driving the toy API with curl commands ===

$ curl -X POST -H 'Content-Type: application/json' -d '{"name":"widget"}' http://127.0.0.1/api/v1/items
  -> 201  {"id": 1, "name": "widget"}

$ curl http://127.0.0.1/api/v1/items/1
  -> 200  {"id": 1, "name": "widget"}

$ curl -X PUT -d '{"name":"gadget"}' http://127.0.0.1/api/v1/items/1
  -> 200  {"id": 1, "name": "gadget"}

$ curl http://127.0.0.1/api/v1/items
  -> 200  [{"id": 1, "name": "gadget"}]

$ curl -X DELETE http://127.0.0.1/api/v1/items/1
  -> 204  

$ curl http://127.0.0.1/api/v1/items/1
  -> 404  {"error": "no such item"}

=== Parse then rebuild a curl command ===
parsed : CurlRequest(method='POST', url='http://127.0.0.1/api/v1/items', headers={'Content-Type': 'application/json'}, data='{"name":"widget"}')
rebuilt: curl -X POST -H 'Content-Type: application/json' -d '{"name":"widget"}' http://127.0.0.1/api/v1/items
```

## Steps

1. Predict each status code before running the demo. Why is the DELETE answer 204 with no body?
2. Send `DELETE /api/v1/items` (the collection). You get 405: the verb is not allowed on that endpoint.
3. Add a `PATCH` handler that updates only provided fields. Add a test.
4. **Security exercise:** `_create` ignores everything except `name`. Change it to copy the whole body into the item, then POST `{"name":"x","id":999,"owner":"admin"}`. That is **mass assignment**. Revert and add a test that extra fields are ignored.
5. Add an `owner` to each item and a `X-User` header; make GET return 404 for items owned by someone else. You have just written an object-level authorization check (see [chapter 11](../../../11-api-authorization-and-oauth/README.md)).

## Run the real tool (hedged)

Against your course lab API (replace host and token):

```bash
BASE=https://api.lab; H="Authorization: Bearer $TOKEN"
curl -s -X POST "$BASE/api/v1/items" -H "$H" --json '{"name":"widget"}' -w '\n%{http_code}\n'
curl -s "$BASE/api/v1/items/1" -H "$H"
curl -s -X PUT "$BASE/api/v1/items/1" -H "$H" --json '{"name":"gadget"}'
curl -s -X DELETE "$BASE/api/v1/items/1" -H "$H" -w '%{http_code}\n'
```

In Postman, import any of these with Import → Raw text ([guide](../../real-tools/postman-and-alternatives.md)).

## What you learned

- Endpoints name resources; verbs change their state; status codes report the result.
- A curl command is a complete, shareable description of one request.
- Every CRUD operation needs its own authorization and input rules.
