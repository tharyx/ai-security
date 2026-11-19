# Real tools: testing authorization, JWTs and OAuth (hedged)

The offline labs teach the ideas without any tool. In your course lab environment you will usually use the tools below. Commands and extension names change: **check `--help`, the BApp Store and the project pages for your version.**

> Only test systems you own or have written permission to test.

## Burp Suite: two-user testing for BOLA and BFLA

1. Log in as **user A** and **user B** in two browser profiles (or use two Burp projects).
2. Browse as A with Burp proxying. In **Proxy → HTTP history**, send an object request (for example `GET /api/v1/users/101/location`) to **Repeater**.
3. Replace A's ID with B's ID and send. A `200` with B's data is BOLA.
4. Replace A's session header with B's (or with none) on admin requests. A `200` is BFLA or missing authentication.
5. For many IDs, send the request to **Intruder**, mark the ID, use a **Numbers** payload, and sort by status and length. (Intruder is throttled in Community Edition.)

**Extensions** (verify current names and maintenance in the BApp Store):

- **Autorize:** paste a low-privilege user's cookie or header; Autorize replays every request you make as admin with the low-privilege session and colours results "bypassed", "enforced" or "unknown".
- **AuthMatrix:** define users, roles and requests in a matrix and run them all, good for regression.
- **JWT Editor:** decode, edit, re-sign JWTs; built-in attacks for `alg:none`, embedded JWK and key confusion.

ZAP by Checkmarx offers similar access-control testing through its **Access Control** add-on (verify availability).

## jwt_tool and hashcat (JWT forging)

```text
python3 jwt_tool.py <token>                       # decode and show claims
python3 jwt_tool.py <token> -X a                  # alg=none variants
python3 jwt_tool.py <token> -C -d wordlist.txt    # crack an HS256 key
python3 jwt_tool.py <token> -T -S hs256 -p "<key>"  # tamper and re-sign
hashcat -m 16500 jwt.txt wordlist.txt             # GPU cracking of HS256 keys
```

## OAuth testing

- Run **Keycloak** in the course lab (container), create a public client, require PKCE, set exact redirect URIs, and watch the flow in Burp.
- Tamper with `redirect_uri` (prefix, subdomain, path traversal), remove `state`, replay a code, remove `code_verifier`, and send an ID token to the API. Each should fail on a well-configured setup; compare with the [oauth-flows lab](../labs/oauth-flows/README.md).
- Read the AS discovery document (`/.well-known/openid-configuration`) and check `grant_types_supported`, `response_types_supported` (no `token`), `code_challenge_methods_supported` (contains `S256`).

## Policy engines

```text
opa eval -d policy.rego -i input.json "data.trips.authz.allow"
opa test . -v
```

**Cedar** has a CLI (`cedar authorize ...`) and **OpenFGA** has the `fga` CLI (`fga model write`, `fga tuple write`, `fga query check`). Verify subcommands with `--help`.
