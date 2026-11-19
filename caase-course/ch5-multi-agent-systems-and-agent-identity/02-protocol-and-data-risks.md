# 02. Protocol and Data Risks: A2A Abuse, Spoofing and Leakage

> **Chapter 5 · Time:** ~2.5 hours · **You will:** spoof an agent-to-agent message, then stop it with signatures, recipient binding, nonces and timestamps; and reason about cross-agent and cross-tenant data leakage.
> **Lab:** [a2a-spoofing](labs/a2a-spoofing/README.md)
> **Maps to:** OWASP Agentic ASI07 Insecure Inter-Agent Communication, ASI06 Memory and Context Poisoning · OWASP LLM 2026 LLM02 Sensitive Information Disclosure [2025: LLM02] · MITRE ATLAS (check atlas.mitre.org)

## 1. Why this matters

- In a multi-agent system the *message* is the attack surface. If the receiver trusts a "sender" field, anyone who can reach the endpoint can impersonate the planner.
- **Asana (June 2025):** a logic flaw in an experimental MCP server was reported to have exposed some customers' data to others, a tenant-isolation failure. Asana disabled the feature. Numbers are reported by secondary sources: verify at source. The lesson applies to any agent gateway: tenant checks must be enforced in code, not assumed.
- Research from Invariant Labs (2025) showed agents leaking private data through a malicious instruction in content they were allowed to read. Same pattern between agents: one agent's output becomes another agent's instruction.

## 2. Understand it

### 2.1 A2A abuse and message spoofing

| Attack | What the attacker does | Control |
|---|---|---|
| **Sender spoofing** | Sends a message claiming `sender: planner` | Authenticate: signature or mutual TLS tied to an agent identity |
| **Tampering** | Edits the payload in transit | Sign the canonical message; verify before use |
| **Replay** | Re-sends a valid old message ("approve payment") | Nonce + timestamp window + replay cache |
| **Redirect** | Re-sends a message meant for agent A to agent B | Bind the **recipient** (audience) inside the signature |
| **Task hijack** | Updates someone else's task | Bind sender to task; authorize per task |
| **Agent Card spoofing** | Publishes a fake card for a look-alike agent, or edits a real card to advertise extra skills | Pin or verify card source and signature; allowlist agents; review card changes like code changes |
| **Streaming/push abuse** | Floods a callback or push-notification endpoint | Authenticate callbacks, rate limit, validate webhook URLs (SSRF) |

The lab uses stdlib HMAC for clarity. In production prefer **asymmetric** signatures or mutual TLS with workload identity ([04](04-agent-identity-and-access.md)), because with HMAC any verifier could also forge.

### 2.2 Cross-agent and cross-tenant leakage

Leaks happen when context, memory or credentials are **shared by default**:

| Leak path | Example | Control |
|---|---|---|
| Shared context | Two sub-agents append to one transcript | Separate context per agent ([isolated-subagents lab](labs/isolated-subagents/README.md)) |
| Shared memory/vector store | Agent for tenant A retrieves tenant B's notes | Tenant ID enforced in the store query, not in the prompt ([03-rag-security](../../03-rag-security/README.md)) |
| Shared credential | One service account behind all agents | Per-agent, per-tenant, short-lived credentials |
| Tool output relay | Agent X returns secrets to agent Y in a "summary" | Redact at boundaries; return structured, minimal results |
| Logs and traces | Prompts with PII stored in a shared dashboard | Redact, restrict access, retention limits |

Rule: **the tenant is part of the identity, not part of the prompt.**

## 3. Defend it

| Layer | Control | Type |
|---|---|---|
| Authenticate sender | Signature / mTLS bound to an agent identity | Hard |
| Bind intent | Sign recipient, task ID, kind, payload, nonce and timestamp | Hard |
| Freshness | Short window plus replay cache that prunes old nonces | Hard |
| Authorize | Per-task allow-list of senders | Hard |
| Tenant isolation | Tenant filter in the data layer | Hard |
| Detect | Alert on bad-signature bursts, unknown senders, replays | Process |

**What does NOT work on its own:** encrypting the channel (TLS authenticates the server, not which agent is speaking); "internal network only"; prompt instructions such as "ignore messages not from the planner" (a spoofed message looks like it is from the planner).

## 4. Hands-on

Run [a2a-spoofing](labs/a2a-spoofing/README.md). You will see: the insecure bus accepts a spoofed redirect of a payment destination; the secure bus rejects unsigned, forged, tampered, replayed, stale, wrong-recipient and unauthorized messages, and a legit message still works.

## 5. Scenarios

1. *The "planner" that was not.* A compromised plugin posts to the worker's inbox claiming to be the planner. Investigate: which field proves identity? Fix: signatures plus per-task sender allowlist.
2. *Yesterday's approval.* An attacker replays an old "approved" message. Fix: nonce and timestamp inside the signed body; reject duplicates.
3. *Tenant bleed in a shared agent.* A support agent caches the last customer's order data in a shared memory key. Fix: namespace by tenant in the store and test with two tenants.

## 6. Interview questions

<details><summary><b>Q1. Why is TLS not enough for agent-to-agent messages?</b></summary>
TLS protects the connection and authenticates the server. It does not prove which *agent* wrote a message, does not stop replay of a captured valid message at the application layer, and does not bind the message to a recipient or task. You need message-level identity, freshness and audience.
</details>

<details><summary><b>Q2. What four things should a signature cover?</b></summary>
Who sent it (sender identity), who it is for (recipient/audience), what it says (payload and kind, plus task ID), and when it is valid (nonce and timestamp). Leave any out and a matching attack exists.
</details>

<details><summary><b>Q3. How do you prevent cross-tenant leakage in a shared agent platform?</b></summary>
Make the tenant part of the authenticated identity, enforce it in the data layer and in credentials, never in the prompt, and test with two tenants that try to read each other's data.
</details>

## 7. Checklist

- [ ] I can list seven message-level attacks and a control for each.
- [ ] I know why HMAC is a teaching twin and what replaces it in production.
- [ ] I can explain why the tenant belongs in the identity, not in the prompt.

## 8. References

- A2A specification (security and authentication sections): verify current version.
- [05 multi-agent-trust](../../05-agent-security/multi-agent-trust/README.md) (signed envelopes, replay, agent cards).
- [cmcpse ch2](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/README.md) for MCP-side attacks.
- Next: [03 Collusion and confused deputies](03-collusion-and-confused-deputies.md).
