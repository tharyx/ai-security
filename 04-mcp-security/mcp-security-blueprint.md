# MCP Security Blueprint

## MCP security model
MCP introduces a protocol-mediated trust boundary between an AI host/client and external servers that expose tools, resources or prompts. Security must cover identity, server trust, tool discovery, invocation, content, transport, secrets and audit.

## Core controls
- Register approved MCP servers; block unregistered/unknown servers.
- Authenticate clients and servers using supported, correctly configured mechanisms.
- Validate issuer, audience, expiry, scopes and token binding requirements where applicable.
- Never pass a token issued for one service to another service.
- Apply least privilege per user, agent, server and tool.
- Treat tool descriptions, resource contents and returned values as untrusted.
- Validate tool arguments with strict schemas and business rules.
- Enforce authorization at the tool/service boundary.
- Restrict network egress and file-system access.
- Use timeouts, payload limits and concurrency quotas.
- Log caller identity, server identity, tool, resource, decision, result class and correlation ID; redact secrets.
- Pin dependencies, verify artifacts and review server updates.

## Threat scenarios
| Scenario | Defensive control |
|---|---|
| Token leakage | Secret manager, scoped tokens, redaction, rotation |
| Scope creep | Explicit scopes and per-tool authorization |
| Tool poisoning | Approved registry, review metadata, behavior tests |
| Command injection | No shell concatenation; typed allowlisted operations |
| Prompt injection in resources | Mark external content untrusted; no authority transfer |
| SSRF | Egress allowlist, DNS/IP validation, block metadata endpoints |
| Shadow server | Inventory, discovery, network policy and endpoint governance |
| Missing audit | Structured immutable/security-centralized logs |
| Context over-sharing | Per-session and per-principal context isolation |
| Dependency tampering | Lockfiles, provenance, SBOM and signed artifacts |

## Lab — secure tool broker
Build a local broker with:
1. approved server registry;
2. tool allowlist;
3. typed JSON input schema;
4. authenticated principal context;
5. policy check;
6. timeout and payload limits;
7. structured audit event;
8. denied-by-default behavior.

Pseudo-flow:
```python
def invoke_tool(principal, server_id, tool_name, args):
    server = registry.require_approved(server_id)
    tool = server.tools.require_allowed(tool_name)
    validated = tool.schema.validate(args)
    policy.authorize(principal, server, tool, validated)
    with timeout(tool.max_runtime_seconds):
        result = tool.handler(validated)
    audit.record(principal=principal.id, server=server_id,
                 tool=tool_name, decision="allow")
    return sanitize_result(result)
```

## MCP security test cases
- Unapproved server is rejected.
- Expired/wrong-audience token is rejected.
- User cannot invoke an admin-only tool.
- Tool arguments outside schema are rejected.
- Tool output containing instruction-like text does not grant authority.
- Tool cannot access arbitrary local paths or internal network targets.
- Excessive calls are rate limited.
- Audit records correlate request, identity and action.
- Server update triggers dependency and behavior review.

## Important implementation note
MCP protocol and authorization behavior evolve. Use the current official specification and SDK documentation for the exact transport, authorization and security requirements of the version deployed. Do not copy authentication snippets from an old tutorial without checking the current specification.
