# Lab: HTTP anatomy, status codes, stateless vs stateful

**Course items:** "Anatomy of a HTTP Request", "Anatomy of a HTTP Response", "HTTP Response Codes and Its Significance", "Stateless and Stateful Requests". **Lesson:** [02 HTTP for APIs](../../02-http-protocol-for-apis.md).

**Time:** 45 minutes. **Tests:** 8, offline. **Safety:** pure parsing of strings in memory; no sockets. The bearer token is FAKE and built at runtime. Only test systems you own or have written permission to test.

## Goal

Read a raw HTTP request and response the way a proxy shows them, know what every status class means, and see in code why a stateless API keeps no server memory while a stateful one does.

## Files

| File | Role |
|---|---|
| [httpmsg.py](httpmsg.py) | `parse_request`, `parse_response`, `build_response`, `status_class`, `StatelessApi`, `StatefulApi`, `make_fake_token` |
| [demo.py](demo.py) | prints a parsed request, a table of status codes, and both API styles |
| [test_aps_ch08_http_anatomy.py](test_aps_ch08_http_anatomy.py) | the tests |

## Run

```text
.venv/Scripts/python appsec-course/08-api-fundamentals-and-architecture/labs/http-anatomy/demo.py
.venv/Scripts/python -m pytest appsec-course/08-api-fundamentals-and-architecture/labs/http-anatomy -q
```

## Real output (token value changes each run)

```text
=== Request anatomy ===
method : GET
target : /api/v1/orders/42
version: HTTP/1.1
headers: {'host': 'shop.example', 'authorization': 'Bearer FAKE-d6c591c76635-DEMO', 'accept': 'application/json'}

=== Response codes ===
  200 OK                     -> Success
  201 Created                -> Success
  301 Moved Permanently      -> Redirection
  401 Unauthorized           -> Client error
  404 Not Found              -> Client error
  429 Too Many Requests      -> Client error
  500 Internal Server Error  -> Server error

=== Stateless API (token on every call, no server memory) ===
with token : 200
no token   : 401
server_state_entries: 0

=== Stateful API (server-side session keyed by cookie) ===
Set-Cookie : session=d836cbdaa07a7d84; HttpOnly; Secure; SameSite=Lax; Path=/
with cookie: 200 -> ok: alice -> /me
server_state_entries: 1
```

## Steps

1. Read `parse_request`. Note that header names are lower-cased: HTTP header names are case-insensitive, so `Authorization` and `authorization` are the same header.
2. Change the demo's request line to `GET /api/v1/orders/42` (no version). The parser raises `malformed request line`. Real servers answer 400 here.
3. In `StatelessApi`, a call without a token returns 401 with `WWW-Authenticate: Bearer`. Why does the server not "remember" that you sent a token one call earlier?
4. In `StatefulApi`, delete the session from `_sessions` and repeat the call: that is logout. Now think about how you would log out a stateless JWT before it expires (short lifetime, deny list).
5. Remove `HttpOnly` from the cookie in `login`. Which attack does that enable? (Any XSS can read the session id with `document.cookie`; see [chapter 10](../../../10-api-authentication/03-authentication-defenses-and-token-storage.md).)

## Run the real tool (hedged)

```bash
curl -v https://httpbin.org/get          # -v prints the request and response headers (> and <)
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/missing
```

Use a public echo service or your course lab target. In Burp Suite or ZAP, the same anatomy is shown in the request/response panes ([chapter 09 Burp guide](../../../09-api-tooling-and-reconnaissance/real-tools/burp-suite-for-apis.md)).

## What you learned

- A request is request line + headers + blank line + optional body; a response is status line + headers + blank line + body.
- The first digit of a status code tells you the class; 401 vs 403 vs 404 are security signals.
- Stateless APIs authenticate every call; stateful designs keep a server session keyed by a cookie, which brings CSRF and session-management concerns.
