# Lab: defending OAuth scopes on an MCP server

**Course exercise:** Defending OAuth scopes on MCP server · **Lesson:** [02 Authentication and authorization](../../02-authentication-and-authorization.md) · **Deeper OAuth lab:** [Module 04, authentication](../../../../04-mcp-security/authentication/README.md)

Offline, standard library only. Tokens are HMAC-signed JWT-like strings (real systems use RS256/ES256 and a JWKS). Tests: `test_oauth_scopes.py` (12).

| File | Role |
|---|---|
| [`oauth_scopes.py`](oauth_scopes.py) | `Issuer` (a toy authorization server that mints whatever it is asked), `ScopedServer` (the resource server), `ToolPolicy` (tool to scopes, client to maximum scopes) |
| [`demo.py`](demo.py) | Six requests that show each defence |

The server checks, in order: signature, expiry, issuer, **audience**, **over-scope**, then **per-tool scope**. Tools missing from the policy are denied. `tools/list` shows only what the token can call. The 403 names the missing scope in a `WWW-Authenticate` value. Switches `check_audience=False` and `check_over_scope=False` reproduce the bugs.

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-oauth-scopes/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-oauth-scopes
```

Real demo output:

```text
reader reads a note                          -> {'result': 'hello'}
reader tries to write                        -> {'error': {'status': 403, 'code': 'insufficient_scope', 'detail': "missing ['notes:write']", 'www_authenticate': 'Bearer error="insufficient_scope", scope="notes:write"'}}
token minted for the calendar server         -> {'error': {'status': 401, 'code': 'invalid_token', 'detail': 'wrong audience', 'www_authenticate': 'Bearer resource_metadata="https://notes-mcp.acme.example/.well-known/oauth-protected-resource"'}}
wildcard scope token                         -> {'error': {'status': 403, 'code': 'over_scoped', 'detail': "token holds scopes it should not: ['*']"}}
unlisted tool, admin token                   -> {'error': {'status': 403, 'code': 'tool_not_allowed', 'detail': 'notes.export'}}
tools/list for the reader: {'result': {'tools': [{'name': 'notes.read'}]}}
```

## Your tasks

1. Turn off `check_audience` and replay the wrong-audience token. Explain the confused deputy in two sentences.
2. Add a tool `notes.share` that needs `notes:share`. Add the scope to `admin-app` only. Write three tests (allowed, missing scope, over-scoped client).
3. Add a `nbf` (not before) test and a clock-skew allowance of 30 seconds. Where should skew be limited?
4. Replace HMAC with an asymmetric signature (hint: `cryptography` Ed25519) so the server cannot mint tokens.
