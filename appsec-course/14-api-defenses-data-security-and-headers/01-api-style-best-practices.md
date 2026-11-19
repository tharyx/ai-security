# Lesson 01: GraphQL, SOAP and REST API Security Best Practices

**Syllabus items covered:** "GraphQL API Security Best Practices", "SOAP API Security Best Practices", "REST API Security Best Practices" ([CASP 7]).

**Time:** 75 minutes. **Lab:** [api-best-practice-checklists](labs/api-best-practice-checklists/README.md). **Attacks** on these styles are in [chapter 12](../12-input-validation-and-injection/README.md) (GraphQL attack lab) and [chapter 13](../13-owasp-api-top-10-and-other-threats/README.md) (GraphQL, SOAP, microservices). This lesson is the **defense** side.

> **DBA analogy.** A database has general hardening (patches, least-privilege grants, auditing) and engine-specific settings (Oracle `REMOTE_LOGIN_PASSWORDFILE`, SQL Server `xp_cmdshell`). APIs are the same. Some controls apply to every API, and some depend on the style.

## 1. Controls every API needs

Whatever the style, the base is the same. Each item maps to earlier chapters:

| Control | Why | Chapter |
|---|---|---|
| TLS everywhere, HSTS for browser clients | Confidentiality and integrity in transit | [02 section 6](02-data-security-and-password-storage.md#6-securing-data-in-transit-using-tls) |
| Strong authentication; short-lived tokens | Who is calling | [10](../10-api-authentication/README.md) |
| Object-, property- and function-level authorization | What they may touch | [11](../11-api-authorization-and-oauth/README.md) |
| Schema validation of every input; output allowlists | Injection, mass assignment, data exposure | [12](../12-input-validation-and-injection/README.md) |
| Rate limits, size limits, timeouts | Resource consumption, brute force | [lesson 04](04-rate-limiting-and-api-gateways.md) |
| Generic errors, security logging | No leaks, but evidence | [15](../15-implementing-api-security-mechanisms/README.md) |
| An inventory of every API and version | You cannot protect what you do not know about | [16](../16-api-security-the-devsecops-way/README.md) |

## 2. GraphQL API security best practices

GraphQL has **one endpoint** (usually `POST /graphql`), and the **client** decides the shape of the query. So route-based controls (WAF rules per URL, gateway rate limits per path) see almost nothing. Controls must sit **inside** the GraphQL server.

| Practice | What it stops | Typical setting |
|---|---|---|
| Disable **introspection** in production | Free schema download (hidden admin mutations, internal fields) | Apollo Server `introspection: false`; graphql-java instrumentation |
| Disable **field suggestions** | "Did you mean `internalNotes`?" rebuilds the schema even with introspection off (tools like Clairvoyance do this) | Server option or error masking |
| **Depth limit** (for example 7–10) | Deep or circular queries (`friends { friends { friends ... } } }`) | `graphql-depth-limit`, MaxQueryDepthInstrumentation |
| **Cost / complexity limit** | One query asking for `first: 10000` on nested lists | Cost analysis with per-field weights |
| **Alias limit** and **batching limit** | 1,000 login or OTP guesses in **one** HTTP request, which bypasses per-request rate limits | Count aliases; reject array batches or cap them |
| **Authorization in every resolver** (or a shared data-access layer) | BOLA through nested fields: `order(id: 5) { customer { paymentMethods } }` | Check ownership where the object is loaded, not at the HTTP layer |
| **Persisted queries** / operation allowlist | Arbitrary queries from attackers; your own clients only send known operation hashes | Apollo persisted queries, Relay compiled queries |
| **Mask errors** | Stack traces, SQL, resolver names | Generic error with a correlation id |
| **Timeouts** and pagination limits | Slow resolvers and huge lists | Per-request execution timeout |

The **DataLoader** pattern (batching database calls) is a performance tool. It does not do authorization. Put the owner check in the loader's query, or after it.

## 3. SOAP API security best practices

SOAP is XML over HTTP with a formal contract (WSDL) and its own security standard (**WS-Security**). Most SOAP risks come from the **XML parser** and from **signature handling**.

| Practice | What it stops |
|---|---|
| **Disable DTDs** (and with them external entities and entity expansion) | XXE: reading `file:///etc/passwd`, SSRF to internal URLs, and the "billion laughs" memory bomb |
| **Validate against the XSD**, with size limits | Unexpected elements, oversized messages, deeply nested XML |
| **WS-Security done right:** require a signature **and** a timestamp (and nonce) | Tampering and replay |
| **Process only the element that was signed** | **XML Signature Wrapping (XSW):** the attacker moves the signed body into a header and inserts a new unsigned body. The signature still verifies, and a naive app processes the unsigned copy. Resolve the signed element by ID and process **that** node. |
| Check that the **SOAPAction** header matches the body operation | SOAPAction spoofing, where a gateway allows "GetBalance" but the body says "Transfer" |
| Do not publish the **WSDL** in production (or require auth for it) | A complete map of operations and types for attackers |
| Generic **SOAP faults** | Stack traces and internal class names |
| TLS (mutual TLS for B2B partners) | Transport security; WS-Security adds message-level protection that survives intermediaries |

Parser settings by language (verify for your version):

- **Java:** `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` on `DocumentBuilderFactory`; similar settings on SAX and StAX factories.
- **.NET:** `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }` (the default in modern .NET).
- **Python:** `defusedxml` for untrusted XML; the standard library's `xml.etree` does not fetch external entities, but older versions were open to entity expansion. Chapter 13's SOAP lab rejects DOCTYPE outright.

## 4. REST API security best practices

REST spreads functions across many **routes**, with object ids in paths (`/v2/orders/{id}`). Its typical failures are missing checks on one route among hundreds.

| Practice | Notes |
|---|---|
| HTTPS only, HSTS | No plain HTTP listener, even for redirects on internal APIs |
| **Every route authenticated** unless explicitly public | Deny by default. Mark public routes (`/health`) on purpose. |
| **Object-level authorization** on every `{id}` route | Like adding `WHERE owner_id = :me` to every query. A VPD/row-level security policy is the database equivalent. |
| **Function-level authorization** for admin routes | Separate admin APIs, scopes or roles; never "hidden" URLs |
| Validate requests against a **schema** (OpenAPI), reject unknown fields | Stops mass assignment and type confusion |
| **Response allowlists** (DTOs) | Never serialize the whole ORM object (BOPLA / excessive data exposure) |
| Rate limits per client and per user; **cap page sizes** | API4:2023 |
| Correct **HTTP methods** and status codes; disable `TRACE` | `405` for wrong methods |
| Strict `Content-Type` checking | Prevents parser confusion and some CSRF tricks (`text/plain` form posts) |
| CORS allowlist; security headers on JSON responses (`no-store`, `nosniff`) | [Lesson 03](03-security-headers-csp-and-cors.md) |
| **Versioning and inventory:** retire old versions | `v1` left running after `v2` launched is a "zombie API" (API9:2023) |
| Idempotency keys for payments and orders | Replays and double submits |

## 5. Scenario: the forgotten staging GraphQL

A fintech team hardens its production GraphQL API: introspection off, depth 8, alias limit 10. Six months later an intern finds `staging-api.example.in/graphql` on a public certificate transparency log. On staging, introspection is on and there is no alias limit. The schema shows a `resetPin(user, pin)` mutation. A 2,000-alias query tries every 4-digit PIN in two requests. Staging uses a nightly copy of production data.

**Lessons:** the checklist must run on **every** environment the internet can reach (the lab's `GQL-01` only exempts non-production; question that). Staging should never hold real customer data. And the inventory (chapter 16) should have listed the staging host.

## 6. Common mistakes

- Trusting the gateway to do GraphQL authorization: it sees one URL.
- Turning off introspection and thinking the schema is secret (suggestions, client bundles and error messages still leak it).
- Validating the SOAP signature, then processing a different node.
- "We have a WAF" as the answer to XXE. Fix the parser.
- Documenting `v2` while `v1` keeps running without the new checks.

## 7. Checklist

- [ ] I can list five GraphQL-specific controls and say why a gateway cannot do them.
- [ ] I can explain XXE, billion laughs and XML Signature Wrapping, and the parser setting or check for each.
- [ ] I can list ten REST controls and map them to the OWASP API Top 10 2023.
- [ ] I have run the lab and made each weak config pass.

## References

- OWASP GraphQL Cheat Sheet; OWASP XML External Entity Prevention Cheat Sheet; OWASP Web Service Security Cheat Sheet; OWASP REST Security Cheat Sheet (verify current names at cheatsheetseries.owasp.org).
- OWASP API Security Top 10 2023 (owasp.org/API-Security).
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (2012), the classic XML Signature Wrapping paper.
- GraphQL over HTTP specification, and the Apollo and graphql-java security docs.
