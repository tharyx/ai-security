# Lesson 04: MCP and agentic threat libraries

> **Chapter 3** · **Time:** ~2.5 hours · **You will:** use MITRE ATLAS, the OWASP LLM Top 10, the OWASP MCP Top 10, the OWASP Agentic Top 10, a 2026 STRIDE/DREAD paper and MCPThreatHive, the AI Incident Database, the MIT AI Risk Repository and an AI threat map to enrich a threat model.

| | |
|---|---|
| **Syllabus lines** | MCP and Agentic Threat Libraries (6 lines) |
| **Already in this repo** | General libraries: [CAISP ch5, lesson 04](../../caisp-course/ch5-threat-modeling-ai-systems/04-ai-threat-libraries.md). ATT&CK vs ATLAS: [CAISP ch2](../../caisp-course/ch2-understanding-and-attacking-llms/README.md). OWASP MCP Top 10 with lab proof: [Module 04](../../04-mcp-security/README.md#owasp-mcp-top-10-2025-beta-coverage). Agentic Top 10: [Module 05](../../05-agent-security/README.md) |
| **Lab** | `owasp_mcp` and `asi` fields in [`mcp_threat_library.yaml`](labs/stride-mcp-architecture/mcp_threat_library.yaml) |

A library answers "what else could go wrong?" and gives findings a shared name. Names and numbers below change; check each source before quoting.

---

## 1. MITRE ATLAS for agentic systems

ATLAS is the ATT&CK-style knowledge base of attacker tactics and techniques against AI systems (atlas.mitre.org). It describes **what an attacker does, step by step** (reconnaissance, initial access, execution, persistence, and so on, through exfiltration and impact). The tactic list in the course is in [CAISP ch2](../../caisp-course/ch2-understanding-and-attacking-llms/README.md). Tactic names have been renamed ("ML Model Access" became "AI Model Access"); verify at the site.

Using it for MCP:

* **Initial access** via a compromised server or package (supply chain); a malicious tool description (indirect prompt injection).
* **Execution** by getting the agent to call a tool the attacker wants.
* **Exfiltration** through an allowed tool (email, HTTP, a second MCP server).
* ATLAS has added techniques for agents and tools in 2025 and later (for example around tool invocation and context poisoning; verify the exact names and ids on the site, because ids move).
* Case studies in ATLAS show real attack chains. Read one and redraw it on your DFD.

Use ATLAS in the threat model as **attack paths** over your DFD: pick a tactic path and ask whether each step is possible on your architecture.

## 2. OWASP LLM Top 10 relevance to MCP

The OWASP Top 10 for LLM Applications has three editions in play (2023 v1.1, 2025, 2026; see [CAISP ch3](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md)). Say which edition you use. MCP touches most entries:

| LLM risk (2025 names) | How it shows up with MCP | OWASP MCP id |
|---|---|---|
| Prompt Injection | Tool results and descriptions carry instructions | MCP03, MCP06 |
| Sensitive Information Disclosure | Tool results, logs and descriptions leak secrets | MCP01, MCP10 |
| Supply Chain | Malicious server packages, typosquats, updates | MCP04, MCP09 |
| Data and Model Poisoning | Poisoned resources or RAG sources a server exposes | MCP06 |
| Improper Output Handling | Tool results rendered or executed downstream | MCP05, MCP06 |
| Excessive Agency | Too many tools, too many scopes, no approval | MCP02 |
| System Prompt Leakage (2026: Hidden Context Exposure) | Tool descriptions or system prompts leak internals | MCP01 |
| Unbounded Consumption | Tool loops, large outputs | MCP08 |

The 2023 entry "LLM07 Insecure Plugin Design" is the ancestor of today's tool and MCP security work. In later editions it was folded into Excessive Agency and Improper Output Handling.

## 3. Emerging MCP-specific threat taxonomies

* **OWASP MCP Top 10 (2025, beta).** MCP01 Token Mismanagement and Secret Exposure; MCP02 Privilege Escalation via Scope Creep; MCP03 Tool Poisoning; MCP04 Software Supply Chain Attacks and Dependency Tampering; MCP05 Command Injection and Execution; MCP06 Prompt Injection via Contextual Payloads; MCP07 Insufficient Authentication and Authorization; MCP08 Lack of Audit and Telemetry; MCP09 Shadow MCP Servers; MCP10 Context Injection and Over-Sharing. It is a beta project, so names and order may change. See [Module 04 coverage table](../../04-mcp-security/README.md#owasp-mcp-top-10-2025-beta-coverage) for lab tests that prove each control.
* **OWASP Top 10 for Agentic Applications 2026 (ASI01 to ASI10).** Agent goal hijack, tool misuse, identity and privilege abuse, agentic supply chain, unexpected code execution, memory and context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, rogue agents. Full mapping in [Module 05](../../05-agent-security/README.md).
* **A 2026 academic paper applying STRIDE and DREAD to MCP.** Reported to have found 57 threats across five MCP components (arXiv, March 2026). Hedge: treat the count as "reported", read the paper before quoting it, and note that DREAD scoring is subjective.
* **MCPThreatHive (arXiv, April 2026, reported).** Described as an MCP threat-intelligence platform that collects and organises MCP threats. Hedge: verify the paper and whether the code is available.
* **Vendor and community write-ups.** Invariant Labs (tool poisoning, WhatsApp MCP exfiltration, GitHub MCP private-repo leak), Trail of Bits, and others. Treat as research, check dates.

How to use them: pick the **OWASP MCP Top 10** as the checklist, **ASI** for agent-level behaviour, and **ATLAS** for attack paths. Put the ids in the register (the lab does: `owasp_mcp` and `asi` fields).

## 4. AI Incident Database

The AI Incident Database (incidentdatabase.ai) is a public collection of reports of harms from AI systems. Use it for **evidence**: "has this happened before?" Search for "agent", "tool", "plugin", "MCP", "prompt injection". Use it to raise likelihood ratings with real cases and to prepare stakeholder stories. Most entries are not MCP-specific; the MCP incidents in section 3 of [lesson 01](01-introduction-and-fundamentals.md) are mostly in vendor blogs and CVE databases, so search there too.

## 5. AI Risk Repository

The MIT AI Risk Repository (airisk.mit.edu) is a living database of AI risks collected from many frameworks (the course materials say 1,700+ risks from 74 frameworks; verify the current count). It has a **causal taxonomy** (who, intent, timing) and a **domain taxonomy** (7 domains, 23 subdomains). Use it for **breadth**: after STRIDE, scan the domains (security, privacy, misinformation, malicious actors, human-computer interaction, socioeconomic, system safety) for anything you missed. Many entries are not about MCP; filter on "agents", "tool use" and "security".

## 6. AI Threat Map

There is no single authoritative public "AI Threat Map". The course provides its own. Public relatives (verify each): the CSA MAESTRO layered model for agentic AI, OWASP GenAI threat maps, and vendor "AI risk map" white papers. A good threat map for MCP lays threats over the **lifecycle** (design, build, publish, install, run, update, retire) and over the **layers** (model, host, client, transport, server, backend, registry). Draw one for your system: columns are lifecycle stages, rows are layers, cells are the threats from your register.

## 7. Putting the libraries together

| Library | Question it answers | Use in the lab |
|---|---|---|
| STRIDE | What property can break on this element? | Core algorithm |
| OWASP MCP Top 10 | What do practitioners already agree on for MCP? | `owasp_mcp` |
| OWASP Agentic Top 10 | What can go wrong with autonomous behaviour? | `asi` |
| ATLAS | How would an attacker chain it? | Attack paths on the DFD |
| OWASP LLM Top 10 | LLM-level view for the model part | Cross-check |
| AI Incident Database | Is there proof? | Likelihood evidence |
| AI Risk Repository | Did we miss a whole domain? | Breadth review |
| AI threat map | Where in the lifecycle? | Communication |

## 8. Quick check

1. Which library would you use to describe an attacker's *sequence* of steps?
2. Why should you say "OWASP MCP Top 10 (2025, beta)" and not just "the OWASP list"?
3. Name two threats from the lab library and their OWASP MCP ids.

## 9. References

* atlas.mitre.org; genai.owasp.org; owasp.org/www-project-mcp-top-10 (beta; verify).
* incidentdatabase.ai; airisk.mit.edu.
* The arXiv papers mentioned above (search arXiv for the titles; verify before citing).
