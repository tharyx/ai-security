# 07. AI Firewalls and Runtime Protection for MCP

> **Syllabus:** AI Firewalls and Runtime Protection: AI firewall concepts for agentic workloads, protecting MCP tool invocations at runtime, detecting prompt injection at the gateway level, rate limiting and abuse prevention for MCP endpoints, guardrails for tool output before it reaches the LLM. Hands-on: deploy and configure an AI firewall for an MCP server.
> **Time:** 2 hours. **Lab:** [`mcp-ai-firewall-deploy`](labs/mcp-ai-firewall-deploy/README.md).
> **Link, do not repeat:** the chapter 4 firewall lab [`mcp-ai-firewall`](../ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/) (how the firewall works), [CAISP ch4 AI firewalls](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#ai-firewalls-for-guarding-models) with the [llm-guard-sanitize](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-guard-sanitize/README.md) and [guard-io](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/guard-io/README.md) labs, [09 lesson 06: secure AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md), and the [MCP security gateway mini-project](../../04-mcp-security/README.md#module-mini-project-mcp-security-gateway). This lesson adds the **deploy, operate and tune** side.

## 1. Why this matters

Some risks cannot be fixed in code or caught in CI: a *legitimate* tool returns a web page that contains an attack, a client floods an expensive tool, a model is talked into calling a tool it should not. A **runtime control point** sees every request and every result, so it can enforce policy in one place for many servers.

## 2. AI firewall concepts for agentic workloads

A classic network firewall looks at addresses and ports. An **AI firewall** (also called an AI gateway or guardrail layer) looks at *meaning-bearing content* and at *agent actions*.

```text
 host / client  --->  [ AI FIREWALL / MCP GATEWAY ]  --->  MCP server(s)
                      request path:  method + tool allowlist, argument checks, authz, rate limits
                      response path: injection score, secret redaction, size cap, labelling
                      always:        audit log, metrics, kill switch
```

What is different for agents:

- Traffic is **JSON-RPC with tool calls**, so the unit of policy is a *tool invocation*, not a URL.
- The dangerous content is in the **response** (tool results) as much as in the request: that is how indirect prompt injection reaches the model.
- Decisions need **context**: which user, which agent, which previous calls (a sensitive read followed by an external send).
- Detection is **probabilistic**. Treat the firewall as one layer that reduces risk, not a guarantee: determined attackers evade pattern matching (encodings, other languages, splitting a payload across results).

Where to place it: in a gateway process between host and servers (remote servers), as a local proxy for stdio servers, or inside the host's tool-call hook. One policy for many servers is the benefit; the gateway becoming a single point of failure and of compromise is the cost, so secure it like the most critical component (auth, audit, no logging of secrets).

## 3. Protecting MCP tool invocations at runtime

| Control | What it does | Lab policy key |
|---|---|---|
| **Method allowlist** | Only the JSON-RPC methods you expect | `methods.allow` |
| **Tool allowlist (default deny)** | A tool that is not listed does not exist for clients; `tools/list` is filtered too | `tools.allow` |
| **Description screening** | Drop tools whose descriptions look poisoned before the host sees them | `injection` applied to `tools/list` |
| **Argument limits** | Types, max length, maximum size; reject anything else | `tools.max_string_length` |
| **Per-user authorization** | The user's scope must allow this tool and this tenant | (identity layer; see [authentication](../../04-mcp-security/authentication/README.md)) |
| **Human approval** for sensitive tools | The gateway pauses destructive or external-send tools | (host feature; see [05 permissions](../../05-agent-security/permissions/README.md)) |
| **Egress control** | The server can only reach approved hosts | network policy |
| **Audit** | Who, which tool, decision, reason, argument *hash* | `audit` |

## 4. Detecting prompt injection at the gateway

Signals, from cheap to expensive:

1. **Pattern signals** with weights (override phrases, concealment, "send to URL", role tags). Fast, explainable, easy to evade. Lab: `injection.signals`.
2. **Structural signals:** instructions in data fields that should be plain values; unexpected HTML/markdown comments; invisible Unicode; very long text in a short-answer tool.
3. **Classifier models** (examples: Meta's Prompt Guard, Lakera Guard, LLM Guard's scanners, cloud "prompt shield" services; verify current names and quality). Better recall, add latency and cost, can themselves be attacked.
4. **Behavioral signals:** the sequence matters (private read, then external send), tool calls the user's request did not imply.
5. **Canaries:** plant a fake secret; if it appears in a result or a call, alert.

Actions: **block** (error to the client), **sanitize** (remove matched text), **flag** (pass but alert), **require approval**. Choose per tool: block for high-impact tools, flag for noisy ones.

**Scoring and thresholds.** The lab sums the weights of matched signals (capped at 1.0) and compares with a threshold. That makes the trade-off visible: a low threshold blocks more attacks and more good traffic.

## 5. Rate limiting and abuse prevention

| Technique | Idea | Notes |
|---|---|---|
| Fixed window | N calls per minute | Simple; allows a burst at a window edge |
| **Sliding window** (lab) | N calls in the last T seconds | Smoother; a little more memory |
| Token bucket | Tokens refill at a rate; a call spends one | Allows controlled bursts |
| Concurrency limit | Max in-flight calls | Protects slow tools and SSE streams |
| Per-tool limits | Tighter on expensive or sensitive tools | Lab: `rate_limits.per_tool` |
| Budgets | Cost, tokens, rows, bytes per user per day | Stops "denial of wallet" |
| Loop detection | Same tool and arguments repeated | Agents can loop |
| Backoff signal | Return a clear error (HTTP 429 or a JSON-RPC error) with retry-after | Well-behaved clients slow down |

Key by **authenticated identity**, not only by IP (agents share IPs). Denied calls should not use up quota (the lab tests that). Keep counters in a shared store when you run several gateway instances.

## 6. Guardrails for tool output before it reaches the LLM

The tool result is the most dangerous text the model sees: it is *untrusted content wrapped in a trusted channel*. Layers:

1. **Size cap and truncation** (lab: `output.max_bytes`): limits context flooding and cost.
2. **Secret and PII redaction** (lab: `output.redact`): AWS keys, tokens, email addresses. Redact rather than hope the model will not repeat it.
3. **Injection screening** (section 4) on the result text.
4. **Type and schema enforcement:** if a tool should return a number or a JSON object, reject results that do not match.
5. **Provenance labelling / spotlighting:** wrap external content in clear delimiters and tell the model it is data, not instructions. Helps, does not guarantee.
6. **Strip active content:** HTML/script, markdown images and links that can leak data via URLs (a known exfiltration channel).
7. **Fail closed:** if the inspector errors, return an error, not the raw result.

## 7. Deploy, configure, tune (the lab focus)

A firewall rollout is a change-management exercise:

1. **Policy as code.** The behavior lives in [`firewall.yaml`](labs/mcp-ai-firewall-deploy/firewall.yaml): reviewed, versioned. The loader **validates and fails closed**: a broken policy never deploys.
2. **Start in `monitor` mode.** The gateway logs "would block" and changes nothing. Run for a week on real traffic.
3. **Measure false positives and negatives** with labelled traffic (`tune.py`). Pick the threshold with evidence and write down why.
4. **Switch to `enforce`** per tool or per server, with a rollback plan (the mode is one line).
5. **Operate:** alert on blocks, review the audit log, add signatures from incidents, retest after model or server changes.
6. **Protect the firewall:** authenticate callers, rate limit the firewall itself, never log argument values or secrets, patch it.

Latency and availability: decide *fail-open or fail-closed* explicitly per tool. For tools that can delete or send, fail closed.

## 8. Hands-on

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-ai-firewall-deploy/demo.py
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-ai-firewall-deploy/tune.py
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-ai-firewall-deploy -v
```

Exercises: (1) add a new tool to the allow list and a per-tool limit; (2) add an evasion to `traffic.jsonl` (for example the same attack in French) and see recall drop, then add a signal; (3) compare your results with the chapter 4 [mcp-ai-firewall lab](../ch4-defending-and-hardening-mcp-servers/labs/mcp-ai-firewall/).

## 9. Interview questions

- *Why inspect responses and not just requests?* Indirect prompt injection arrives in tool results; a clean request can return a hostile page.
- *Why start in monitor mode?* To measure false positives on real traffic before blocking real users.
- *A regex firewall blocked an attack in testing. Is the server safe?* No: regexes are evadable; keep least privilege, approvals and egress control underneath.

## 10. References

- [Repo: 04 MCP gateway mini-project](../../04-mcp-security/README.md#module-mini-project-mcp-security-gateway), [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md)
- OWASP LLM Top 10 (prompt injection, improper output handling); LLM Guard, NeMo Guardrails, Prompt Guard documentation (verify current).
