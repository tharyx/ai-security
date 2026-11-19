# Lesson 01: Threat modeling fundamentals for agentic AI

> **Chapter 7** · **Time:** ~2.5 hours · **You will:** run a structured threat model on an agent deployment, and apply MITRE ATLAS and the OWASP Agentic Security Initiative (ASI) across the whole system, not one component.

| | |
|---|---|
| **Syllabus lines** | Threat Modeling Fundamentals for Agentic AI · Structured threat modeling for agents · Applying MITRE ATLAS and the OWASP Agentic Security Initiative across a full agent deployment |
| **Already in this repo** | General method: [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md) (four questions, DFDs, STRIDE, rating). MCP version: [CMCPSE ch3](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/README.md). Agent controls: [05 agent security](../../05-agent-security/README.md) |
| **Lab** | [Lab 1: STRIDE + ATLAS threat model](labs/01-stride-atlas-threat-model/) |
| **Next** | [Lesson 02: trust boundaries and risk scoring](02-trust-boundaries-and-risk-scoring.md) |

---

## 1. Why agents need a different threat model

A classic web app has fixed code paths. An agent decides at run time which tool to call, which peer to ask, and what to remember. That changes three things for the modeler.

| Classic threat model | Agentic threat model |
|---|---|
| Data flows are fixed in code | The agent **chooses** flows at run time, so you model what it *could* do, not only what it usually does |
| Input is data | Input (a web page, a ticket, a peer's artifact) can become **instructions** |
| One actor per request | A chain of actors: user, orchestrator, worker, tool, partner agent. Authority can be diluted or widened at each hop |
| Trust zones are network zones | Trust zones are also **content origins** (who wrote this text?) and **identity origins** (who signed this message?) |

Public incidents show why (hedged, verify at source): prompt-injection research against tool-using assistants, malicious MCP packages such as `postmark-mcp` (2025), and the OpenClaw skill-marketplace abuse reported in early 2026. None is a "model bug". Each is a boundary nobody drew.

## 2. A structured process for agents

Use the four classic questions, with agent-specific prompts. Keep the model in a file (the lab uses YAML) so it can be reviewed when the design changes.

1. **What are we building?** Draw agents, tools, stores and humans as DFD elements. Mark each agent's **autonomy** (low, medium, high), its **tools**, and its **identity**. Draw every protocol on every flow (HTTPS, A2A, MCP, a shared context store).
2. **What can go wrong?** Apply STRIDE per element and per flow, then add the agent questions: can content on this flow become an instruction? can this agent be talked into using a tool outside its job? can this message be forged or replayed?
3. **What will we do about it?** Pick controls that do not depend on the model behaving. Prefer hard controls (signatures, ACLs, schemas, policy outside the model) over soft ones (prompt wording).
4. **Did we do a good enough job?** Turn each control into a test. A threat model with no tests is a document, not a control set. Lab 8 enforces this: every hard control must point to a real test.

### STRIDE for agent elements

| Letter | Agentic example | Typical control |
|---|---|---|
| **S**poofing | A peer claims to be the payments agent; a rogue Agent Card | Signed messages, card verification, mutual auth |
| **T**ampering | Edited message, poisoned shared context, injected artifact | Signatures, schemas, write ACLs, provenance |
| **R**epudiation | No log says which agent asked for the refund | Per-agent identity in every log line |
| **I**nformation disclosure | Context hand-off leaks more than the receiver needs | Minimal context, namespace ACLs |
| **D**enial of service | Delegation loop, fan-out, runaway budget | Depth limits, budgets, circuit breaker |
| **E**levation of privilege | Low-trust agent obtains a high-privilege action through a hand-off | Scope narrowing, invocation allow-list, human approval |

## 3. Applying MITRE ATLAS across a full deployment

ATLAS is a knowledge base of adversary tactics and techniques against AI systems, built like ATT&CK. In 2026 it has about 16 tactics; two renames are worth knowing: "ML Model Access" is now "AI Model Access", and "ML Attack Staging" is now "AI Attack Staging" (a later rename to "AI Attack Adaptation" is reported but unconfirmed). Tactic IDs and names change between releases: **check atlas.mitre.org** and always record the version you used. Background: [CAISP ch2](../../caisp-course/ch2-understanding-and-attacking-llms/README.md).

How to use it on a deployment, not a single model:

* Walk the **kill chain** for each entry point: Reconnaissance (find agents and their cards), Resource Development (publish a rogue agent or skill), Initial Access (a message that gets accepted), Execution (injection runs a tool), Persistence (poisoned memory or shared context), Privilege Escalation (delegation or session abuse), Defense Evasion (downgrade, stay below rate limits), Exfiltration, Impact.
* Tag each threat in your table with the tactic. Lab 1 does this and prints which tactics your threat set covers. Gaps in the tactic list are questions: "we have nothing for Persistence, is that true, or did we not look?"

## 4. Applying the OWASP Agentic Security Initiative

The OWASP GenAI Security Project's Agentic Security Initiative produced guidance on agentic threats and mitigations and the **Top 10 for Agentic Applications 2026** (ASI01 to ASI10). The full list with the repo's controls is in [05-agent-security/README.md](../../05-agent-security/README.md). For protocols the important entries are:

| ASI | Name | Where it shows up in protocols |
|---|---|---|
| ASI01 | Agent Goal Hijack | Injection inside a task, artifact or context entry |
| ASI02 | Tool Misuse and Exploitation | Bridge forwards fields the tool should never see |
| ASI03 | Identity and Privilege Abuse | Delegation and session privilege escalation |
| ASI04 | Agentic Supply Chain Vulnerabilities | Rogue Agent Cards, unpinned peers |
| ASI06 | Memory and Context Poisoning | Shared context store poisoning |
| ASI07 | Insecure Inter-Agent Communication | Spoofing, replay, downgrade |
| ASI08 | Cascading Failures | Delegation loops and fan-out |
| ASI10 | Rogue Agents | Missing identity and kill switch |

A mapping table is not a threat model. Use ASI and ATLAS as **checklists after you draw the system**: for each ASI entry ask "which of my flows does this touch?" An entry that touches no flow is either not applicable (say why) or a blind spot.

The CSA research notes also mention an OWASP "Agent Control Standard" contributed in 2026. Treat that as unconfirmed until you find it on the OWASP site.

## 5. Whole-deployment worked example

Lab 1's [`deployment.yaml`](labs/01-stride-atlas-threat-model/deployment.yaml) is a support platform: customer, partner agent (other org), orchestrator, support agent (reads tickets), refund agent (moves money), a CRM MCP server, a context store, a session store, a payments ledger and an identity provider. Run it:

```text
DFD problems: none
Boundary crossings (flow -> trust change): {'F1': 2, 'F4': -1, 'F5': 3, 'F9': 1, 'F10': 1}
```

Look at F5: the partner's status and artifacts flow into the orchestrator, a trust gain of 3 zones. That is the flow to model first.

## 6. Common mistakes

* Modeling the LLM but not the **protocols between** agents.
* Treating "the agent is ours" as a trust boundary. Same organization is not same trust.
* Listing ATLAS tactics without mapping them to flows.
* Controls with no test.
* Forgetting that the model changes when a spec changes. Record spec versions (A2A v1.0.x, MCP revision).

## 7. Quick checks

<details><summary><b>Q1. Why is "what could the agent do" more important than "what does it usually do"?</b></summary>

Because the agent picks flows at run time. An attacker needs only one reachable path. The model must cover everything the agent's tools, peers and memory allow.
</details>

<details><summary><b>Q2. Give two reasons to keep the threat model as a file.</b></summary>

It can be reviewed in a pull request when the design changes, and tests and validators (lab 8) can check it automatically.
</details>

## References

* MITRE ATLAS: atlas.mitre.org (check the current version)
* OWASP GenAI Security Project, Agentic Security Initiative: genai.owasp.org
* NIST AI 100-2 E2025, Adversarial Machine Learning taxonomy (agent security section; check for newer editions)
* Threat Modeling Manifesto: threatmodelingmanifesto.org
