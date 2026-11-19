# Chapter 5: Multi-Agent Systems and Agent Identity

> **Time:** ~20 hours. **You will:** compare multi-agent topologies, spoof and then sign agent-to-agent messages, exploit and fix a confused-deputy chain, scope delegated tokens hop by hop, contain a rogue agent, and add human approval gates. Every lab is offline and tested.

## Syllabus coverage

Every syllabus line of the chapter, in course order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Multi-Agent Architectures and Topologies | [01 Architectures and protocols](01-multi-agent-architectures-and-protocols.md); repo: [05 multi-agent-trust](../../05-agent-security/multi-agent-trust/README.md) | n/a |
| &nbsp;&nbsp;Orchestrator/sub-agent and swarm topologies | [01, section 2.1](01-multi-agent-architectures-and-protocols.md#21-two-topologies) ([SVG](../../images/caase-ch5-topologies-and-delegation.svg)) | [isolated-subagents](labs/isolated-subagents/README.md) |
| &nbsp;&nbsp;Agent-to-agent (A2A) communication protocols | [01, section 2.2](01-multi-agent-architectures-and-protocols.md#22-how-agents-talk) (A2A v1.x, ACP merged into A2A, MCP vs A2A) | [a2a-spoofing](labs/a2a-spoofing/README.md) |
| &nbsp;&nbsp;Delegation Chains and Task Hand-off Between Agents | [01, section 2.3](01-multi-agent-architectures-and-protocols.md#23-delegation-chains-and-hand-off); [04](04-agent-identity-and-access.md) | [delegator-worker-routing](labs/delegator-worker-routing/README.md), [delegated-token-scoping](labs/delegated-token-scoping/README.md) |
| Protocol and Data Risks | [02 Protocol and data risks](02-protocol-and-data-risks.md) | n/a |
| &nbsp;&nbsp;A2A protocol abuse and message spoofing | [02, section 2.1](02-protocol-and-data-risks.md#21-a2a-abuse-and-message-spoofing) | [a2a-spoofing](labs/a2a-spoofing/README.md) |
| &nbsp;&nbsp;Cross-agent and cross-tenant data leakage | [02, section 2.2](02-protocol-and-data-risks.md#22-cross-agent-and-cross-tenant-leakage); repo: [03 rag-security access control](../../03-rag-security/README.md) | [isolated-subagents](labs/isolated-subagents/README.md) |
| Collusion and Confused Deputies | [03 Collusion and confused deputies](03-collusion-and-confused-deputies.md) | n/a |
| &nbsp;&nbsp;Collusion and cascading failure across an agent swarm | [03, section 2.1](03-collusion-and-confused-deputies.md#21-collusion-and-cascading-failure); repo: [05 multi-agent-trust (ASI08)](../../05-agent-security/multi-agent-trust/README.md) | cascade and depth limits in [confused-deputy-chain](labs/confused-deputy-chain/README.md) |
| &nbsp;&nbsp;Confused-deputy scenarios when agents delegate authority | [03, section 2.2](03-collusion-and-confused-deputies.md#22-the-confused-deputy-in-a-chain) ([SVG](../../images/caase-ch5-confused-deputy.svg)); repo: [04 authentication](../../04-mcp-security/authentication/README.md) | [confused-deputy-chain](labs/confused-deputy-chain/README.md) |
| Agent Identity and Access | [04 Agent identity and access](04-agent-identity-and-access.md); repo: [05 agent-identity](../../05-agent-security/agent-identity/README.md) | n/a |
| &nbsp;&nbsp;Establishing identity for non-human/autonomous actors | [04, section 2.1](04-agent-identity-and-access.md#21-establishing-identity-for-a-non-human-actor) (SPIFFE-style workload identity, hedged); repo: [09 lesson 07](../../09-enterprise-architecture/07-centralized-ai-iam-and-zero-trust.md) | per-agent credentials in [isolated-subagents](labs/isolated-subagents/README.md) |
| &nbsp;&nbsp;Delegated authorization and token scoping between agents | [04, section 2.2](04-agent-identity-and-access.md#22-delegated-authorization-and-token-scoping) ([SVG](../../images/caase-ch5-token-chain.svg)) | [delegated-token-scoping](labs/delegated-token-scoping/README.md) |
| &nbsp;&nbsp;Least-privilege and least-agency permission design | [04, section 2.3](04-agent-identity-and-access.md#23-least-privilege-vs-least-agency); repo: [05 permissions](../../05-agent-security/permissions/README.md) | tool-allowlist tests in [isolated-subagents](labs/isolated-subagents/README.md) |
| Oversight, Containment, and Fail-Safes | [05 Oversight, containment and fail-safes](05-oversight-containment-and-failsafes.md) | n/a |
| &nbsp;&nbsp;Human-in-the-loop vs. human-on-the-loop checkpoints | [05, section 2.1](05-oversight-containment-and-failsafes.md#21-hitl-vs-hotl) ([SVG](../../images/caase-ch5-hitl-hotl.svg)) | [hitl-approval-gate](labs/hitl-approval-gate/README.md) |
| &nbsp;&nbsp;Detecting, containing, and safely terminating a rogue agent | [05, section 2.2](05-oversight-containment-and-failsafes.md#22-detecting-containing-and-safely-terminating-a-rogue-agent); repo: [05 monitoring-and-response](../../05-agent-security/monitoring-and-response/README.md) | [rogue-agent-containment](labs/rogue-agent-containment/README.md) |
| &nbsp;&nbsp;Fail-safe design for high-consequence or physical-world-acting agents | [05, section 2.3](05-oversight-containment-and-failsafes.md#23-fail-safe-design-for-high-consequence-or-physical-world-agents) | `failsafe.py` in [rogue-agent-containment](labs/rogue-agent-containment/README.md) |
| Hands-on Exercises: | see the lab index below; real-tool setup in [06](06-real-tool-guides.md) | |
| &nbsp;&nbsp;Orchestrating a Local and Cloud-Routed Agent Pair in a Delegator/Worker Setup | [01, section 2.4](01-multi-agent-architectures-and-protocols.md#24-local-and-cloud-routed-agents); [06 guide A](06-real-tool-guides.md#a-a-local-plus-cloud-routed-agent-pair-exercise-1) | [delegator-worker-routing](labs/delegator-worker-routing/README.md) |
| &nbsp;&nbsp;Delegating Subtasks to Isolated Subagents Using Hermes Agent | [01](01-multi-agent-architectures-and-protocols.md); [06 guide B](06-real-tool-guides.md#b-delegating-subtasks-to-isolated-sub-agents-with-hermes-agent-exercise-2) (hedged) | [isolated-subagents](labs/isolated-subagents/README.md) |
| &nbsp;&nbsp;Spoofing Agent-to-Agent Messages to Manipulate a Delegated Task | [02](02-protocol-and-data-risks.md) | [a2a-spoofing](labs/a2a-spoofing/README.md) |
| &nbsp;&nbsp;Exploiting a Confused-Deputy Chain Across Delegated Agents | [03](03-collusion-and-confused-deputies.md) | [confused-deputy-chain](labs/confused-deputy-chain/README.md) |
| &nbsp;&nbsp;Scoping and Testing Delegated Authorization Tokens Between Agents | [04](04-agent-identity-and-access.md) | [delegated-token-scoping](labs/delegated-token-scoping/README.md) |
| &nbsp;&nbsp;Detecting and Safely Terminating a Rogue Agent | [05](05-oversight-containment-and-failsafes.md) | [rogue-agent-containment](labs/rogue-agent-containment/README.md) |
| &nbsp;&nbsp;Adding a Human-in-the-Loop Approval Gate to a Multi-Agent Workflow | [05](05-oversight-containment-and-failsafes.md) | [hitl-approval-gate](labs/hitl-approval-gate/README.md) |

## Lab index

| Lab | Course exercise | Offline | Tests | What it proves |
|---|---|---|---|---|
| [delegator-worker-routing](labs/delegator-worker-routing/README.md) | Local and cloud agent pair | yes | 8 | Restricted data never reaches the cloud mock; fail closed |
| [isolated-subagents](labs/isolated-subagents/README.md) | Isolated subagents (Hermes-style) | yes | 6 | Separate context, tools, credentials; bounded untrusted return |
| [a2a-spoofing](labs/a2a-spoofing/README.md) | Spoof A2A messages | yes | 10 | Signatures, recipient binding, replay and staleness checks |
| [confused-deputy-chain](labs/confused-deputy-chain/README.md) | Confused-deputy chain | yes | 9 | Intersection of authority; taint and approval |
| [delegated-token-scoping](labs/delegated-token-scoping/README.md) | Delegated tokens | yes | 10 | Down-scope, audience, `act` chain, expiry |
| [rogue-agent-containment](labs/rogue-agent-containment/README.md) | Rogue agent termination (+ fail-safe controller) | yes | 10 | Ordered termination, evidence, rollback, watchdog |
| [hitl-approval-gate](labs/hitl-approval-gate/README.md) | HITL gate | yes | 11 | Hash-bound, independent, expiring approvals; HOTL veto |

Run all of them:

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity -v
```

## Outdated in the syllabus -> current

| Syllabus says | Current (Nov 2026; verify at source) |
|---|---|
| A2A "protocols" (and ACP) | **A2A** is now an open standard at **v1.x** under the Linux Foundation, and part of the **Agentic AI Foundation** (with MCP). IBM's **ACP merged into A2A** in Aug 2025. "ACP" today may also mean Zed's **Agent Client Protocol**. |
| Agent identity as generic "tokens" | Industry is converging on **workload identity** (SPIFFE-style, cloud workload identity) plus **OAuth token exchange** for delegation; new "agent identity" products are emerging: check vendor docs. |
| Hermes Agent exercise | Hermes Agent is a 2026 open-source harness; commands change quickly: use its current docs and the offline twin for the security lesson. |
| OWASP guidance | Agentic risks have their own **Top 10 for Agentic Applications 2026 (ASI01 to ASI10)**; the LLM Top 10 is now the **2026** list. |

## Learning order

1. [01](01-multi-agent-architectures-and-protocols.md), then [delegator-worker-routing](labs/delegator-worker-routing/README.md) and [isolated-subagents](labs/isolated-subagents/README.md).
2. [02](02-protocol-and-data-risks.md), then [a2a-spoofing](labs/a2a-spoofing/README.md).
3. [03](03-collusion-and-confused-deputies.md), then [confused-deputy-chain](labs/confused-deputy-chain/README.md).
4. [04](04-agent-identity-and-access.md), then [delegated-token-scoping](labs/delegated-token-scoping/README.md).
5. [05](05-oversight-containment-and-failsafes.md), then [hitl-approval-gate](labs/hitl-approval-gate/README.md) and [rogue-agent-containment](labs/rogue-agent-containment/README.md).
6. [06](06-real-tool-guides.md) (optional, in a safe environment), then the Q&As below.

## Exam tips for this chapter

- **Four hop questions:** real principal, scope, lifetime, accountability.
- **Spoofing defenses:** sign sender + recipient + task + payload + nonce + timestamp; TLS alone is not enough.
- **Confused deputy:** the fix is checking the **originating principal** and the **intersection** of authority, not the immediate caller.
- **Token exchange:** scope, expiry and audience only narrow; `act` records the chain; passthrough is the anti-pattern.
- **Least agency** is about autonomy (tools, steps, spend, delegation), not only access.
- **Termination order:** quarantine, drain, preserve, revoke, roll back, destroy and verify.
- **HITL = before, HOTL = during/after with veto.** Know the approval-fatigue and swap attacks.
- **Physical agents:** agent proposes, independent controller disposes; safe state, watchdog, interlock, e-stop, human reset.

## 15 exam-style questions

<details><summary>1. Compare orchestrator/sub-agent and swarm topologies for security.</summary>

Orchestrator/sub-agent has one trust point, easier audit and narrow worker tools, but orchestrator compromise affects all workers. A swarm has no hub, so any peer can influence any peer and failures spread; it needs per-message authentication, budgets and circuit breakers.
</details>

<details><summary>2. What is an A2A Agent Card and why is it a risk?</summary>

A self-description of an agent (name, skills, endpoint, supported auth) published at a well-known URL. It is data an attacker can forge or poison, so you verify its source (and signature where supported), allowlist agents and review card changes.
</details>

<details><summary>3. What happened to ACP, and what does "ACP" mean now?</summary>

IBM BeeAI's Agent Communication Protocol merged into A2A in August 2025 and its repository was archived. Today "ACP" often refers to Zed's Agent Client Protocol (editor to coding agent), so name the one you mean.
</details>

<details><summary>4. What should and should not pass in a hand-off between agents?</summary>

Pass the task, the minimum data and a narrower delegated credential. Do not pass the full transcript, secrets or blanket authority. Treat the returned result as untrusted data.
</details>

<details><summary>5. List the checks a secure agent-to-agent message receiver performs.</summary>

Known sender identity, valid signature over the canonical message, recipient matches, fresh timestamp, nonce not seen before, sender authorized for that task. Then apply the content as data under the receiver's own policy.
</details>

<details><summary>6. How can cross-tenant leakage happen between agents, and how do you stop it?</summary>

Via shared context, shared memory or vector stores, a shared credential, relayed tool output, or shared logs. Enforce the tenant in the authenticated identity and data layer, use per-agent per-tenant credentials, redact at boundaries and test with two tenants.
</details>

<details><summary>7. Explain a confused deputy with an agent example and its fix.</summary>

A finance agent with payment authority executes a request relayed from an injected document because it only checks its own permissions. Fix: carry originating principal and delegated scopes, allow only the intersection, mark content-driven actions as tainted and require human approval for high value.
</details>

<details><summary>8. Why is "the other agent agreed" not a control?</summary>

Agents often share models and context, so they can agree for the same wrong reason or be steered by the same injected text. Use deterministic checks and independent human review for high-impact decisions.
</details>

<details><summary>9. What properties make an agent identity good?</summary>

Unique per agent, cryptographically verifiable, short-lived, attributable (agent + principal logged) and revocable independently. SPIFFE-style workload identity is one way to get it (verify platform support).
</details>

<details><summary>10. What does token exchange enforce on each hop?</summary>

Scope can only shrink, audience is rebound to the next resource, expiry cannot exceed the parent's, the `act` chain extends, depth is capped, and tokens can be revoked by ID.
</details>

<details><summary>11. Why is audience binding important?</summary>

A token valid only for resource X is useless if stolen from X and replayed at Y. It stops token passthrough and confused-deputy abuse across services.
</details>

<details><summary>12. Least privilege vs least agency?</summary>

Least privilege limits what an identity may access. Least agency limits what an agent may decide and do on its own: tools, steps, spend, delegation and self-modification. You need both.
</details>

<details><summary>13. Name five approval-gate design rules.</summary>

Fixed risk table, approve the exact action hash, independent approver (two for irreversible), expiry and single use, cap on pending approvals, raise risk for tainted actions, show raw details and origin chain.
</details>

<details><summary>14. Give the safe termination order for a rogue agent and why evidence comes before destroy.</summary>

Quarantine, drain, preserve evidence, revoke credentials, roll back side effects, destroy and verify. Evidence must exist before the context is destroyed, otherwise you lose the record of what happened.
</details>

<details><summary>15. How do you make a physical-world agent fail safe?</summary>

Separate safety controller enforcing limits and interlocks, a watchdog the agent cannot disable, a defined safe state, a hardware e-stop, human-only reset, and testing of failure paths, following the relevant functional-safety standards.
</details>

## References

- Lessons 01 to 06 in this folder.
- A2A project documentation and specification (Linux Foundation / Agentic AI Foundation): verify version.
- OWASP Top 10 for Agentic Applications 2026 and "Agentic AI: Threats and Mitigations" (OWASP GenAI Security Project).
- RFC 8693, RFC 8707; SPIFFE/SPIRE docs; NIST SP 800-207.
- Hermes Agent docs: hermes-agent.nousresearch.com (verify before use).
- Previous: Chapter 4. Next: [Chapter 6](../ch6-operationalizing-agentic-ai-security/README.md).
