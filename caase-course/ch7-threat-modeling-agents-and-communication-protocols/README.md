# Chapter 7: Threat modeling agents and communication protocols

> **Time:** ~20 hours · **You will:** threat-model a multi-agent deployment with STRIDE, MITRE ATLAS and the OWASP Agentic Security Initiative, map trust boundaries and score agentic risks, understand A2A, ACP and the "UCP" of the syllabus, attack and defend inter-agent protocols in simulation, and build a protocol-level threat model and control set with tests.

## Outdated in the syllabus → current

> **The syllabus may be old. Use this box first.** Facts verified for this companion in November 2026; always verify at the source.

| Syllabus says | Current picture |
|---|---|
| **A2A** as a new Google protocol | **A2A v1.0** shipped in 2026 (v1.0.x patches after); it lives in the Linux Foundation and was accepted into the **Agentic AI Foundation (AAIF)**. Field and method names changed from pre-1.0 drafts: check the spec |
| **ACP**, the Agent Communication Protocol | IBM BeeAI's ACP **merged into A2A in August 2025** and its repo was archived with a migration guide. Today "ACP" often means **Zed's Agent Client Protocol** (editor to coding agent). Session and state *concepts* are still worth knowing |
| **UCP**, "Unified Context Protocol" for shared context exchange | **No standard with that name was found.** The concept is a **shared context store** across agents. The real **UCP is Google's Universal Commerce Protocol** (announced 11 Jan 2026, agentic commerce; works with AP2, MCP and A2A). Labs here build a "UCP-style shared context store (course term)" |
| MCP as the tool layer | Still correct. MCP moved to the Linux Foundation's AAIF (Dec 2025); standard transports are stdio and Streamable HTTP; check the latest spec revision |
| MITRE ATLAS tactics from older material | About 16 tactics in 2026; "ML Model Access" is now "AI Model Access", "ML Attack Staging" is now "AI Attack Staging" (a further rename is reported, unconfirmed). Check atlas.mitre.org |
| OWASP guidance for agents | **Top 10 for Agentic Applications 2026** (ASI01 to ASI10) from the OWASP GenAI Security Project's Agentic Security Initiative |
| No national guidance | NIST AI Agent Standards Initiative (Feb 2026, hedged); CISA with Five Eyes partners, "Careful Adoption of Agentic AI Services" (1 May 2026, hedged) |

## Syllabus coverage

Every syllabus line, in course order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Threat Modeling Fundamentals for Agentic AI | [01](01-threat-modeling-fundamentals-for-agentic-ai.md); method background: [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [CMCPSE ch3](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/README.md) | [Lab 1](labs/01-stride-atlas-threat-model/) |
| &nbsp;&nbsp;Structured threat modeling for agents | [01, sections 1 to 2](01-threat-modeling-fundamentals-for-agentic-ai.md) | `validate()`, `find_threats()` |
| &nbsp;&nbsp;Applying MITRE ATLAS and the OWASP Agentic Security Initiative across a full agent deployment | [01, sections 3 to 5](01-threat-modeling-fundamentals-for-agentic-ai.md); [ASI mapping](../../05-agent-security/README.md) | `atlas`, `asi` fields in [`threat_library.yaml`](labs/01-stride-atlas-threat-model/threat_library.yaml) |
| Trust Boundaries and Risk Scoring for Agentic Systems | [02](02-trust-boundaries-and-risk-scoring.md) ([SVG](../../images/caase-ch7-trust-boundaries.svg)) | [Lab 1](labs/01-stride-atlas-threat-model/) |
| &nbsp;&nbsp;Mapping trust boundaries across single-agent, multi-agent, and cross-organization topologies | [02, section 1](02-trust-boundaries-and-risk-scoring.md); [multi-agent trust](../../05-agent-security/multi-agent-trust/) | `crossings()` |
| &nbsp;&nbsp;Scoring agentic-specific risks | [02, section 2](02-trust-boundaries-and-risk-scoring.md) | `score()` |
| Agent Communication Protocols: A2A, ACP, and UCP | [03](03-agent-communication-protocols.md) ([SVG](../../images/caase-ch7-protocol-stack.svg)) | [Labs 2, 4, 5](labs/) |
| &nbsp;&nbsp;Agent-to-Agent (A2A) protocol | [03, section 2](03-agent-communication-protocols.md) | [Lab 2](labs/02-a2a-message-exchange/) |
| &nbsp;&nbsp;&nbsp;&nbsp;Message structure | [03, section 2.1](03-agent-communication-protocols.md) | `message/send` flow in [`a2a_lite.py`](labs/02-a2a-message-exchange/a2a_lite.py) |
| &nbsp;&nbsp;&nbsp;&nbsp;Capability discovery | [03, section 2.2](03-agent-communication-protocols.md) | `card()`, `A2AClient.discover()` |
| &nbsp;&nbsp;&nbsp;&nbsp;Task delegation | [03, section 2.3](03-agent-communication-protocols.md); [multi-agent trust](../../05-agent-security/multi-agent-trust/) | task states, `statusLog`, follow-up |
| &nbsp;&nbsp;Agent Communication Protocol (ACP) | [03, section 3](03-agent-communication-protocols.md) (merged into A2A; naming collision) | [Lab 4](labs/04-acp-session-abuse/) |
| &nbsp;&nbsp;&nbsp;&nbsp;Session and state management between heterogeneous agents | [03, section 3](03-agent-communication-protocols.md) | `SecureSessions` (generic model) |
| &nbsp;&nbsp;Unified Context Protocol (UCP): | [03, section 4](03-agent-communication-protocols.md) (no such standard found; real UCP explained) | [Lab 5](labs/05-ucp-context-poisoning/) |
| &nbsp;&nbsp;&nbsp;&nbsp;Shared context exchange across agents and orchestrators | [03, sections 4.1 and 4.2](03-agent-communication-protocols.md) | `ContextStore` ("UCP-style", course term) |
| &nbsp;&nbsp;Comparing trust and authentication models across A2A, ACP, and UCP | [03, section 5](03-agent-communication-protocols.md) ([SVG](../../images/caase-ch7-trust-auth-comparison.svg)) | - |
| &nbsp;&nbsp;Intersection and divergence from MCP's tool-layer trust model | [03, section 6](03-agent-communication-protocols.md) ([SVG](../../images/caase-ch7-mcp-vs-agent-trust.svg)); [CMCPSE ch2](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/README.md) | [Lab 6](labs/06-cross-protocol-audit/) |
| Attacking Agent Communication Protocols | [04](04-attacking-agent-communication-protocols.md) ([SVG](../../images/caase-ch7-attack-map.svg)) | [Labs 3 to 7](labs/) |
| &nbsp;&nbsp;Message spoofing and identity forgery across A2A, ACP, and UCP | [04, section 1](04-attacking-agent-communication-protocols.md) | [Lab 3](labs/03-a2a-spoofing-hijack/) |
| &nbsp;&nbsp;Capability-discovery abuse | [04, section 2](04-attacking-agent-communication-protocols.md) | [Lab 3](labs/03-a2a-spoofing-hijack/) (rogue card) |
| &nbsp;&nbsp;Context and state injection through shared UCP context stores | [04, section 3](04-attacking-agent-communication-protocols.md) | [Labs 4 and 5](labs/05-ucp-context-poisoning/) |
| &nbsp;&nbsp;Replay, downgrade, and man-in-the-middle attacks against inter-agent sessions | [04, section 4](04-attacking-agent-communication-protocols.md) | [Labs 3 and 7](labs/07-mutual-auth-signing/) |
| &nbsp;&nbsp;Cross-protocol confusion attacks when an orchestrator bridges multiple protocols | [04, section 5](04-attacking-agent-communication-protocols.md) | [Lab 6](labs/06-cross-protocol-audit/) |
| Defending and Governing Agent Communication Protocols | [05](05-defending-and-governing-agent-protocols.md) | [Labs 3 to 8](labs/) |
| &nbsp;&nbsp;Mutual authentication and message signing across A2A, ACP, and UCP | [05, section 1](05-defending-and-governing-agent-protocols.md) | [Lab 7](labs/07-mutual-auth-signing/) |
| &nbsp;&nbsp;Schema validation and capability allow-listing at the protocol boundary | [05, section 2](05-defending-and-governing-agent-protocols.md) | [Lab 6](labs/06-cross-protocol-audit/) (`strict_schema`), lab 3 (`skill_allow`) |
| &nbsp;&nbsp;Session integrity, replay protection, and secure context-store design | [05, section 3](05-defending-and-governing-agent-protocols.md) | Labs [4](labs/04-acp-session-abuse/), [5](labs/05-ucp-context-poisoning/), [7](labs/07-mutual-auth-signing/) |
| &nbsp;&nbsp;Threat-model-driven controls | [05, section 4](05-defending-and-governing-agent-protocols.md) | [Lab 8](labs/08-protocol-threat-model-builder/) |
| &nbsp;&nbsp;Emerging governance and interoperability standards for agent communication protocols | [05, section 5](05-defending-and-governing-agent-protocols.md) ([SVG](../../images/caase-ch7-governance-landscape.svg)); [governance](../../07-ai-governance/), [compliance](../../08-ai-compliance/) | - |
| Hands-on Exercises: | [06](06-hands-on-exercises.md) | [all eight labs](labs/README.md) |
| &nbsp;&nbsp;Threat Modeling a Multi-Agent Deployment Using STRIDE and MITRE ATLAS | [06](06-hands-on-exercises.md) | [Lab 1](labs/01-stride-atlas-threat-model/) |
| &nbsp;&nbsp;Standing Up an A2A Message Exchange Between Two Local Agents | [06](06-hands-on-exercises.md) | [Lab 2](labs/02-a2a-message-exchange/) |
| &nbsp;&nbsp;Spoofing Agent Identity Over A2A to Hijack a Delegated Task | [06](06-hands-on-exercises.md) | [Lab 3](labs/03-a2a-spoofing-hijack/) |
| &nbsp;&nbsp;Abusing ACP Session State to Escalate Privilege Between Agents | [06](06-hands-on-exercises.md) | [Lab 4](labs/04-acp-session-abuse/) |
| &nbsp;&nbsp;Poisoning a Shared UCP Context Store to Influence Downstream Agents | [06](06-hands-on-exercises.md) | [Lab 5](labs/05-ucp-context-poisoning/) |
| &nbsp;&nbsp;Auditing a Cross-Protocol Orchestrator Bridging MCP, A2A, and UCP | [06](06-hands-on-exercises.md) | [Lab 6](labs/06-cross-protocol-audit/) |
| &nbsp;&nbsp;Implementing Mutual Authentication and Message Signing Across A2A/ACP/UCP | [06](06-hands-on-exercises.md) | [Lab 7](labs/07-mutual-auth-signing/) |
| &nbsp;&nbsp;Building a Protocol-Level Threat Model and Control Set from Scratch | [06](06-hands-on-exercises.md) | [Lab 8](labs/08-protocol-threat-model-builder/) |

**Not run by the repo author:** real A2A SDKs, the Zed Agent Client Protocol, the real Universal Commerce Protocol and AP2 endpoints. The labs are offline teaching models and say so. Use your course environment for the real systems.

## Lab index

See [labs/README.md](labs/README.md). Summary:

| Lab | Topic | Tests |
|---|---|---|
| 01 | STRIDE + ATLAS + ASI model from YAML, agentic scoring | 9 |
| 02 | A2A-style exchange on 127.0.0.1 (card, tasks, artifact) | 8 |
| 03 | Spoofed sender, rogue card, replay; signed and pinned defense | 11 |
| 04 | Session fixation and state tampering; server-side state | 10 |
| 05 | Shared context store poisoning; ACL, signing, trust tier | 10 |
| 06 | Cross-protocol bridge and auditor (4 findings) | 12 |
| 07 | Mutual auth, signing, replay, downgrade (HMAC / Ed25519) | 15 |
| 08 | Threat model + control set template and validator | 10 |

Run: `python -m pytest caase-course/ch7-threat-modeling-agents-and-communication-protocols` (85 tests).

## Learning order

1. [01 Fundamentals](01-threat-modeling-fundamentals-for-agentic-ai.md), then [Lab 1](labs/01-stride-atlas-threat-model/).
2. [02 Trust boundaries and scoring](02-trust-boundaries-and-risk-scoring.md).
3. [03 Protocols](03-agent-communication-protocols.md) with [Lab 2](labs/02-a2a-message-exchange/). Read the outdated box above first.
4. [04 Attacks](04-attacking-agent-communication-protocols.md) with labs 3 to 6.
5. [05 Defense and governance](05-defending-and-governing-agent-protocols.md) with labs 7 and 8.
6. [06 Hands-on](06-hands-on-exercises.md): finish with your own validated threat model.

## Exam and interview tips for this chapter

* **Start every protocol answer with the layer**: MCP is agent-to-tool, A2A is agent-to-agent, commerce protocols (UCP, AP2) are agent-to-merchant.
* **Say the naming facts**: ACP (IBM) merged into A2A; "ACP" can mean Zed's Agent Client Protocol; the syllabus's "Unified Context Protocol" is a concept, and the real UCP is Google's Universal Commerce Protocol.
* **A card is a claim.** Always add "verify, pin, allow-list".
* **Declared is not enforced.** Authentication schemes in a card or spec do nothing until the server checks them.
* **Name what is signed.** Protocol, session, sender, recipient, task, time, nonce.
* **Bridges are boundaries.** Trust is carried, identities namespaced, schemas checked, replay global.
* **Hedge unstable facts**: A2A version numbers, field names, NIST initiative details, the Five Eyes guidance names, ATLAS tactic names.
* **Close with tests**: a control without a test is a wish.

## 15 interview / exam-style questions

<details><summary><b>Q1. How is MCP's trust model different from A2A's?</b></summary>

MCP connects a host to deterministic tool servers: the client controls the server, and the main risks are poisoned tool text, rug pulls and token handling. A2A connects peer agents that reason, may be in other organizations and can delegate onward. Authority is negotiated per task, so identity, scope narrowing, discovery trust and delegation limits matter more.
</details>

<details><summary><b>Q2. What is an Agent Card, and why is it a security issue?</b></summary>

A machine-readable description of an agent: name, skills, endpoint, supported content types and authentication schemes. It is how clients discover capabilities. It is a claim made by the host. A rogue or changed card can win delegation, so verify it (signature, issuer), pin it after review and allow-list skills per caller.
</details>

<details><summary><b>Q3. What happened to IBM's Agent Communication Protocol?</b></summary>

It merged into A2A in August 2025; the repository was archived with a migration guide. Today the acronym is often used for Zed's Agent Client Protocol, which links editors and coding agents. Always check which one a document means.
</details>

<details><summary><b>Q4. The syllabus lists "Unified Context Protocol". What do you say?</b></summary>

No standard with that name was found. The concept is a shared context store across agents. The real UCP is Google's Universal Commerce Protocol (Jan 2026) for agentic commerce, working with AP2, MCP and A2A. Treat the syllabus term as course vocabulary and verify with your instructor.
</details>

<details><summary><b>Q5. Walk through hijacking a delegated task by spoofing identity, and the fix.</b></summary>

The orchestrator delegates a task and records the assignee. An attacker who knows the task id sends a result whose sender says "payments-agent". A receiver that trusts the field accepts it. Fix: per-agent signatures over sender, recipient, task id, body, time and nonce; verify with the key of the claimed sender; require sender equals assignee and the task still open.
</details>

<details><summary><b>Q6. How do you defend capability discovery?</b></summary>

Accept only cards signed by your issuer and on a per-skill allow-list; pin card hashes after review; re-verify on change; choose peers by policy, not by self-description; and limit what a card's new skills can do until reviewed.
</details>

<details><summary><b>Q7. Explain session fixation and state tampering between agents.</b></summary>

Fixation: the attacker plants a session id and a privileged agent authenticates into it, so the attacker holds a privileged session. Tampering: state handed to another agent is unsigned, so the attacker edits the role. Fix: random ids regenerated on login and privilege change, server-side state with the role re-read each call, signed tokens bound to the agent with expiry and revocation.
</details>

<details><summary><b>Q8. How can a shared context store be poisoned, and what stops it?</b></summary>

A low-trust writer writes values or instruction text that a higher-trust agent later reads. Stop it with default-deny write ACLs per namespace, signed entries verified on read, provenance and trust tiers (low-trust text is data), read ACLs, TTL and audit. Prompt wording alone is not a control.
</details>

<details><summary><b>Q9. What is a downgrade attack in inter-agent sessions?</b></summary>

An on-path attacker edits the list of offered authentication suites so peers fall back to a weaker one, or to none. Defenses: a policy floor that refuses weak suites, and binding the offered list into the authenticated handshake transcript so edits are detected. A floor of "none" for compatibility defeats both.
</details>

<details><summary><b>Q10. What bugs do you look for in a cross-protocol orchestrator?</b></summary>

Trust level not carried across protocols; identity mapped by display name so identities collide; schema mismatches and pass-through of extra or coerced fields; replay stores kept per protocol so the same message works twice. Fixes: carry origin trust, namespace identities as protocol:org/name, strict per-tool schemas, one replay store, and a protocol label in the signature.
</details>

<details><summary><b>Q11. What should a signed inter-agent message cover?</b></summary>

Protocol label, session id, sender, recipient, task id, timestamp, nonce and body. Each field blocks one attack: cross-protocol replay, wrong session, redirect, result swapping, stale replay and tampering.
</details>

<details><summary><b>Q12. Why prefer asymmetric signatures across organizations?</b></summary>

The verifier holds only public keys and cannot sign as the peer. With a shared secret, either party (or anyone who steals it) can forge messages. Asymmetric keys also make rotation and revocation easier at scale.
</details>

<details><summary><b>Q13. How do you score agentic risk differently from a classic app?</b></summary>

Start with likelihood times impact, then adjust for autonomy, privilege and tool reach, exposure to untrusted content, boundary gain, delegation depth and persistence. Show inherent and residual risk and tie high scores to hard controls with tests.
</details>

<details><summary><b>Q14. What are the main security considerations of the real UCP, and how sure are you?</b></summary>

Conceptually: merchant impersonation, mandate (payment authorization) abuse or replay, injected catalog content steering the agent's purchase, identity-linking token leaks, bridge confusion and fraud or dispute handling. I would hedge details and verify against the UCP and AP2 specifications, because the protocols are new and still changing.
</details>

<details><summary><b>Q15. Who governs agent protocols, and what does that give you?</b></summary>

MCP (Dec 2025) and A2A (2026) are under the Linux Foundation's Agentic AI Foundation, which gives neutral, open governance. NIST has an AI Agent Standards Initiative (Feb 2026, hedged) and CISA with Five Eyes partners published agentic AI guidance (May 2026, hedged). None of this replaces your own threat model: keep a protocol register, pin versions and re-review when a spec changes.
</details>

## References

All hedged: verify titles, versions and dates at the source.

* A2A specification and project site: a2a-protocol.org (v1.0, Agent Card, security sections)
* Agentic AI Foundation announcement (Linux Foundation): MCP contribution (Dec 2025) and A2A acceptance (2026)
* IBM BeeAI ACP repository: archived with the ACP-to-A2A migration guide (Aug 2025)
* Zed, Agent Client Protocol: zed.dev (naming collision with IBM's ACP)
* Google announcement of the Universal Commerce Protocol (Jan 2026) and the AP2 specification
* Model Context Protocol specification: modelcontextprotocol.io
* MITRE ATLAS: atlas.mitre.org
* OWASP GenAI Security Project: Top 10 for Agentic Applications 2026; Agentic AI Threats and Mitigations
* NIST AI RMF 1.0, AI 600-1, AI 100-2 E2025; NIST AI Agent Standards Initiative (Feb 2026)
* CISA and partners, "Careful Adoption of Agentic AI Services" (1 May 2026)
* Repo: [multi-agent trust](../../05-agent-security/multi-agent-trust/), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [CMCPSE ch3](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/README.md)
