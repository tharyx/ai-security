# Chapter 3: Threat modeling MCP architectures

> **Time:** ~15 hours · **You will:** model an MCP deployment (host, clients, servers, OAuth, registry) with data flow diagrams and STRIDE, use MCP and agentic threat libraries, rate and rank the risks, and explain the result to stakeholders.

## Syllabus coverage

Every syllabus line of the chapter, in course order. Method lessons that are not MCP-specific live in the CAISP companion and are linked.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to Threat Modeling | [01 Introduction](01-introduction-and-fundamentals.md) | - |
| &nbsp;&nbsp;What is threat modeling? | [01, section 1](01-introduction-and-fundamentals.md); general: [CAISP ch5 lesson 01](../../caisp-course/ch5-threat-modeling-ai-systems/01-threat-modeling-foundations.md) | - |
| &nbsp;&nbsp;Why threat model MCP systems specifically? | [01, section 2](01-introduction-and-fundamentals.md) | - |
| &nbsp;&nbsp;Threat modeling challenges in agentic AI environments | [01, section 3](01-introduction-and-fundamentals.md) | - |
| &nbsp;&nbsp;Threat modeling benefits for MCP practitioners | [01, section 4](01-introduction-and-fundamentals.md) | - |
| Threat Modeling Fundamentals | [01, section 5](01-introduction-and-fundamentals.md) | - |
| &nbsp;&nbsp;What are assets in an MCP context? | [01, 5.1](01-introduction-and-fundamentals.md) | `assets:` in [`mcp_architecture.yaml`](labs/stride-mcp-architecture/mcp_architecture.yaml) |
| &nbsp;&nbsp;Weaknesses vs vulnerabilities in MCP | [01, 5.2](01-introduction-and-fundamentals.md) | - |
| &nbsp;&nbsp;Risk management stages | [01, 5.3](01-introduction-and-fundamentals.md); [05, section 3](05-rating-and-managing-risks.md) | risk register output |
| &nbsp;&nbsp;The STRIDE methodology | [01, 5.4](01-introduction-and-fundamentals.md); [03](03-stride-for-mcp.md) | [`stride_mcp.py`](labs/stride-mcp-architecture/stride_mcp.py) |
| Diagramming MCP Architectures | [02 Diagramming](02-diagramming-mcp-architectures.md) | `--mermaid` output |
| &nbsp;&nbsp;Introduction to Data Flow Diagrams (DFDs) | [02, section 1](02-diagramming-mcp-architectures.md); [CAISP ch5 lesson 02](../../caisp-course/ch5-threat-modeling-ai-systems/02-dfd-and-llm-architecture.md) | `validate()` rules |
| &nbsp;&nbsp;DFD components in the MCP context | [02, section 2](02-diagramming-mcp-architectures.md) | [`mcp_architecture.yaml`](labs/stride-mcp-architecture/mcp_architecture.yaml) |
| &nbsp;&nbsp;Diagramming a simple single-server MCP architecture | [02, section 3](02-diagramming-mcp-architectures.md) ([SVG](../../images/cmcpse-ch3-dfd-single-server.svg)) | - |
| &nbsp;&nbsp;Diagramming a complex multi-server agentic pipeline | [02, section 4](02-diagramming-mcp-architectures.md) ([SVG](../../images/cmcpse-ch3-dfd-multi-server.svg)) | [`mcp_architecture.yaml`](labs/stride-mcp-architecture/mcp_architecture.yaml) |
| &nbsp;&nbsp;Identifying and drawing trust boundaries between hosts, clients, and servers | [02, section 5](02-diagramming-mcp-architectures.md) | `crossings()` |
| Applying STRIDE to MCP | [03 STRIDE for MCP](03-stride-for-mcp.md) | [`labs/stride-mcp-architecture/`](labs/stride-mcp-architecture/) |
| MCP and Agentic Threat Libraries | [04 Threat libraries](04-mcp-threat-libraries.md) | [`mcp_threat_library.yaml`](labs/stride-mcp-architecture/mcp_threat_library.yaml) |
| &nbsp;&nbsp;MITRE ATLAS for agentic systems | [04, section 1](04-mcp-threat-libraries.md); [CAISP ch2](../../caisp-course/ch2-understanding-and-attacking-llms/README.md) | - |
| &nbsp;&nbsp;OWASP LLM Top 10 relevance to MCP | [04, section 2](04-mcp-threat-libraries.md); [2023 vs 2026](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) | - |
| &nbsp;&nbsp;Emerging MCP-specific threat taxonomies | [04, section 3](04-mcp-threat-libraries.md) (OWASP MCP Top 10, ASI, 2026 STRIDE/DREAD paper, MCPThreatHive; last two hedged) | `owasp_mcp`, `asi` fields |
| &nbsp;&nbsp;AI Incident Database | [04, section 4](04-mcp-threat-libraries.md) | browse incidentdatabase.ai |
| &nbsp;&nbsp;AI Risk Repository | [04, section 5](04-mcp-threat-libraries.md) | browse airisk.mit.edu |
| &nbsp;&nbsp;AI Threat Map | [04, section 6](04-mcp-threat-libraries.md) | - |
| Rating and Managing Risks | [05 Rating and managing risks](05-rating-and-managing-risks.md) | [`labs/risk-rating/`](labs/risk-rating/) |
| &nbsp;&nbsp;Risk rating methodology for MCP-specific threats | [05, section 1](05-rating-and-managing-risks.md) | `rate()` |
| &nbsp;&nbsp;Prioritizing findings from a threat model | [05, section 2](05-rating-and-managing-risks.md) | `rank()`, `group_by_mitigation()` |
| &nbsp;&nbsp;Risk management strategies and mitigations | [05, section 3](05-rating-and-managing-risks.md); defences in [Chapter 4](../ch4-defending-and-hardening-mcp-servers/README.md) | `treatment()` |
| &nbsp;&nbsp;Communicating threat model outputs to stakeholders | [05, section 4](05-rating-and-managing-risks.md); [exec one-pager template](exec-summary-template.md) | `exec_summary()` |
| Hands-on Exercises: | [06 Hands-on exercises](06-hands-on-exercises.md) | all four labs |
| &nbsp;&nbsp;Apply STRIDE to a provided MCP architecture and document findings | [06](06-hands-on-exercises.md); [03](03-stride-for-mcp.md) | [`stride-mcp-architecture/`](labs/stride-mcp-architecture/README.md), [`findings-template.md`](labs/stride-mcp-architecture/findings-template.md) |
| &nbsp;&nbsp;Risk rating exercise on STRIDE findings | [06](06-hands-on-exercises.md); [05](05-rating-and-managing-risks.md) | [`risk-rating/`](labs/risk-rating/README.md) |
| &nbsp;&nbsp;Threat modeling with IriusRisk for an MCP deployment | [`iriusrisk-walkthrough.md`](labs/iriusrisk-walkthrough.md) (conceptual, hedged); CAISP: [05 section 5](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md) | [OWASP Threat Dragon alternative + Mermaid DFD](labs/threat-dragon/README.md) |
| &nbsp;&nbsp;Threat Modeling with STRIDEGPT | [`stridegpt/README.md`](labs/stridegpt/README.md) | [`stridegpt_offline.py`](labs/stridegpt/stridegpt_offline.py), [`validation-checklist.md`](labs/stridegpt/validation-checklist.md) |

**Not run by the repo author:** IriusRisk (commercial; the walkthrough is conceptual) and the real STRIDE GPT (needs a key or a local model). The offline twin and the Mermaid/Threat Dragon route cover the same learning goals.

## Learning order

1. [01 Introduction and fundamentals](01-introduction-and-fundamentals.md): assets, weakness vs vulnerability, STRIDE.
2. [02 Diagramming](02-diagramming-mcp-architectures.md): DFDs and trust boundaries.
3. [03 STRIDE for MCP](03-stride-for-mcp.md) and the [STRIDE lab](labs/stride-mcp-architecture/README.md).
4. [04 Threat libraries](04-mcp-threat-libraries.md).
5. [05 Rating and managing risks](05-rating-and-managing-risks.md) and the [risk-rating lab](labs/risk-rating/README.md).
6. [06 Hands-on](06-hands-on-exercises.md): IriusRisk or Threat Dragon, then STRIDE GPT and the validator.

Run the chapter tests: `python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures` (35 tests).

## Exam and interview tips for this chapter

* **Name the MCP boundary correctly.** The transport between client and server is the boundary. Host and client share one zone.
* **Tool definitions and tool results are data flows from a lower-trust zone into the model.** This is the answer to many "what is different about MCP" questions.
* **Say the edition** of every list: "OWASP MCP Top 10 (2025, beta)", "OWASP LLM Top 10 2025", "Agentic Top 10 2026".
* **Hedge unstable facts:** counts from the 2026 STRIDE/DREAD paper, MCPThreatHive details, ATLAS tactic names, MCP spec revision numbers.
* **Inherent vs residual.** Always give both and say which controls changed the number.
* **Executives get decisions, engineers get findings.** Be ready to rewrite one finding for both.

## 15 interview / exam-style questions

<details><summary><b>Q1. Why does MCP need its own threat model, not only an LLM threat model?</b></summary>

MCP adds third-party servers, a tool catalogue assembled at run time, several transports and an OAuth layer. The text that servers send (definitions and results) goes into the model's context, so servers become part of the control plane. Local servers also run with the user's privileges. An LLM-only model misses these boundaries.
</details>

<details><summary><b>Q2. Name five assets in an MCP deployment.</b></summary>

OAuth tokens and API keys; tool definitions; resources (files, rows); conversation context; host configuration (mcp.json); server code and dependencies; the audit trail. Each has different threats and controls.
</details>

<details><summary><b>Q3. Weakness versus vulnerability, with an MCP example.</b></summary>

A weakness is a kind of flaw (OS command injection, CWE-78). A vulnerability is a specific instance in a product (CVE-2025-6514 in mcp-remote, where an untrusted authorization endpoint reached command execution; severity reported as critical). A threat is what an attacker could do with it; risk is likelihood and impact.
</details>

<details><summary><b>Q4. Where are the trust boundaries in a host with one stdio server and one remote OAuth server?</b></summary>

User to host; host/client to the stdio server (different process and author); host/client to the remote server (network, TLS, OAuth); host to the authorization server; host to the LLM provider; and each server to its backend. Host and client are in one zone.
</details>

<details><summary><b>Q5. Which STRIDE letters apply to each DFD element type?</b></summary>

External entity: S and R. Process: S, T, R, I, D, E. Data store: T, R, I, D. Data flow: T, I, D. Boundary-crossing flows deserve extra attention and a higher likelihood.
</details>

<details><summary><b>Q6. Give one STRIDE threat for each letter on an MCP host.</b></summary>

S: connects to an impostor server. T: accepts a poisoned or changed tool description. R: no log of who approved a call. I: leaks one server's data through another. D: a tool-call loop exhausts budget. E: runs side-effect tools without approval.
</details>

<details><summary><b>Q7. How would you model the tool definitions in a DFD?</b></summary>

As data that flows from the server process to the host and onward to the LLM. They are untrusted input with control-plane power, so the flow is a Tampering and Information-disclosure target, and changes after approval (rug pull) are a separate threat.
</details>

<details><summary><b>Q8. A local MCP server listens on 127.0.0.1. What are the threats?</b></summary>

Any local program or web page may reach it: DNS rebinding, CSRF-style calls from a browser, and unauthenticated use (the MCP Inspector issue CVE-2025-49596 is an example). Controls: bind to loopback only, require a token, check Host and Origin.
</details>

<details><summary><b>Q9. What are the OWASP MCP Top 10 and how reliable is it?</b></summary>

A list of ten MCP-specific risks (MCP01 Token Mismanagement and Secret Exposure to MCP10 Context Injection and Over-Sharing). It is a beta project from 2025, so names and order may change. Use it as a checklist, cite the version, and verify at owasp.org.
</details>

<details><summary><b>Q10. What do ATLAS, the OWASP lists and the AI Incident Database each give you?</b></summary>

ATLAS: attacker tactics and techniques, good for attack paths. OWASP lists: a checklist of common risks. AI Incident Database: evidence of real harms, good for likelihood and stakeholder stories. The MIT AI Risk Repository adds breadth across domains.
</details>

<details><summary><b>Q11. How do you rate an MCP threat with the OWASP method?</b></summary>

Likelihood is the mean of threat agent and vulnerability factors; impact is the mean of technical and business factors (0 to 9 each). Convert each to LOW, MEDIUM or HIGH and read the matrix to get Note, Low, Medium, High or Critical. In the lab, a boundary crossing adds to the agent factor and each existing control lowers the vulnerability factor to give residual risk.
</details>

<details><summary><b>Q12. Three findings are all High. How do you order them?</b></summary>

By residual score, then by crown-jewel assets, reachability (remote before local-only), whether one finding enables others (logging gaps hide everything), and cost to fix. Group by the control that closes the most findings.
</details>

<details><summary><b>Q13. What are the four risk treatments, with an MCP example of each?</b></summary>

Avoid: do not install a server that needs shell access. Mitigate: pin tool hashes, enforce scopes. Transfer: vendor contract or insurance. Accept: missing TLS on a protected loopback port, with an owner and an expiry date.
</details>

<details><summary><b>Q14. What goes on an executive one-pager?</b></summary>

The bottom line (safe, safe with conditions, not safe) in two sentences; top five risks in plain words with severity now and after the fix; the decisions needed with cost and deadline; counts by severity; assumptions and accepted risks; the next review date.
</details>

<details><summary><b>Q15. How do you use an AI threat-modeling tool such as STRIDE GPT safely?</b></summary>

As a brainstorming aid, not an authority. Send a synthetic or sanitised description, validate the output against a manual STRIDE pass: coverage of STRIDE letters and crossings, MCP-specific misses, invented components, correct mappings, real incidents only. Keep the model, date and prompt with the draft.
</details>

## References

* MCP specification and security best practices: modelcontextprotocol.io (verify the current revision).
* OWASP MCP Top 10 (beta), OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic Applications 2026: genai.owasp.org and owasp.org.
* MITRE ATLAS: atlas.mitre.org. AI Incident Database: incidentdatabase.ai. MIT AI Risk Repository: airisk.mit.edu.
* STRIDE GPT: github.com/mrwadams/stride-gpt. OWASP Threat Dragon: owasp.org/www-project-threat-dragon.
* OWASP Risk Rating Methodology; Shostack, *Threat Modeling*.
* Related in this repo: [Module 04](../../04-mcp-security/README.md), [Module 05](../../05-agent-security/README.md), [CAISP ch5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md).
