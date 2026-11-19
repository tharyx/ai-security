# Real tools: Postman, and offline alternatives (hedged)

**Course items:** "Postman", "Ability To Talk to an API", "Performing CRUD Operations Using API" ([CASP 2]). **Offline equivalent:** the [toy-api-crud lab](../labs/toy-api-crud/README.md) drives CRUD with curl commands against an in-process API.

> Only test systems you own or have written permission to test. Features and pricing change: **verify on the vendor sites**.

## Postman in 2026 (verify)

- Desktop and web app; **most features need a signed-in Postman account**, and collections, environments and history sync to Postman's cloud. The old offline "Scratch Pad" was retired years ago (verify current status).
- **Collections** = saved requests in folders. **Environments** = variables (`{{baseUrl}}`, `{{token}}`). **Current value vs initial value:** only initial values sync and are shared; still treat any synced workspace as potentially visible to others.
- **Authorization tab:** No Auth, Basic, Bearer, API Key (header or query), OAuth 2.0 (authorization code with PKCE, client credentials; it can fetch tokens for you), AWS Signature and more.
- **Import:** OpenAPI 3.x, Swagger 2.0, cURL commands, HAR files. "Import → Raw text" accepts a `curl` command.
- **Scripts** (pre-request and tests) in JavaScript, and the **Collection Runner** / **Newman** CLI (`newman run collection.json -e env.json`) for CI.
- **Proxy:** Settings → Proxy, to route through Burp/ZAP (see [Burp guide](burp-suite-for-apis.md)).

## A CRUD walk-through (lab target)

1. Create an environment `lab` with `baseUrl = http://127.0.0.1:8000` and `token = <your FAKE lab token>` (mark it secret).
2. `POST {{baseUrl}}/api/v1/items`, Body → raw → JSON `{"name":"widget"}` → expect **201** and a `Location` header.
3. `GET {{baseUrl}}/api/v1/items/1` → **200**.
4. `PUT {{baseUrl}}/api/v1/items/1` with `{"name":"gadget"}` → **200**.
5. `DELETE {{baseUrl}}/api/v1/items/1` → **204**; repeat the GET → **404**.
6. Tests tab: `pm.test("created", () => pm.response.to.have.status(201));`
7. Security variants: remove the token (expect 401), use a second user's token on item 1 (expect 403/404), add `"owner_id": 2` to the POST body (should be ignored).

## Safety notes

- **Never** store production secrets in a public or team workspace. Real-world leaks have come from public Postman workspaces containing live keys.
- Use secret-type variables and short-lived test credentials. Rotate anything that was ever synced by mistake.
- Disable "SSL certificate verification" only for a lab environment, never globally.

## Alternatives

| Tool | Why consider it |
|---|---|
| **Bruno** | open source, offline-first; collections are plain files you keep in Git (`.bru`) |
| **Insomnia** | Kong's client; local storage options (check current account requirements) |
| **HTTPie** (CLI and desktop) | readable CLI syntax: `http POST :8000/api/v1/items name=widget` |
| **curl + a shell script** | fully reproducible, works in every exam lab |
| **VS Code REST Client** / JetBrains HTTP client | `.http` files next to your code |

## Exam pointers

- Know how to import an OpenAPI file and a cURL command into Postman.
- Know where to set auth once for a whole collection (collection-level Authorization tab).
- Know the risk of synced workspaces and how environments reduce copy-paste of secrets.
