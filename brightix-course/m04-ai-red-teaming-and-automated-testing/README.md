# Module 04: AI Red Teaming & Automated Adversarial Testing (days 16–22)

A structured red-team method for LLMs, RAG and agents: ATLAS mapping, multi-turn and encoding attacks, indirect injection through content, automated scanning in the style of garak and PyRIT, agentic privilege escalation, and reporting.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 4] AI Red Teaming Methodology & MITRE ATLAS Threat Mapping | [Security testing](../../02-llm-security/security-testing/README.md); [ATT&CK vs ATLAS](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md); [Capstone red team](../../10-capstone-project/03-red-team-and-incident-exercise.md) | [00-atlas-mapping](../../caisp-course/ch2-understanding-and-attacking-llms/labs/00-atlas-mapping); [security-testing lab](../../02-llm-security/security-testing/lab) | Covered |
| [BX 4] Multi-Turn Adversarial Jailbreaking & Encoding Evasion Techniques | [Jailbreak module (Crescendo, encodings)](../../02-llm-security/jailbreak/README.md); [Attacking the reasoning loop](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/03-attacking-the-reasoning-loop.md) | [jailbreak lab](../../02-llm-security/jailbreak/lab); [07-encoding-and-refusal-suppression-demo](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/07-encoding-and-refusal-suppression-demo); **NEW** [garak-pyrit-style-scanner (multi-turn)](labs/garak-pyrit-style-scanner) | Covered |
| [BX 4] Indirect Prompt Injection Payloads via Documents, Web & Emails | [Prompt injection module](../../02-llm-security/prompt-injection/README.md); [Browser and computer-use agents](../../caase-course/ch4-computer-use-browser-and-coding-agents/04-attacking-browser-and-computer-use-agents.md); [MCP attack primitives](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/03-mcp-attack-primitives.md) | [prompt-injection lab](../../02-llm-security/prompt-injection/lab); [browser-agent-page-injection](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/browser-agent-page-injection) | Covered |
| [BX 4] Automated Vulnerability Scanning with Garak & PyRIT | [Security testing tools](../../02-llm-security/security-testing/README.md); [DevSecOps tooling for AI](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md); **NEW** [garak and PyRIT guide](real-tools/garak-and-pyrit.md) | **NEW** [garak-pyrit-style-scanner](labs/garak-pyrit-style-scanner); [llm-agent-vuln-scan](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan) | Gap filled here |
| [BX 4] Red Teaming Agentic Workflows & Privilege Escalation Paths | [MCP attack primitives](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/03-mcp-attack-primitives.md); [Agent permissions](../../05-agent-security/permissions/README.md) | [05-cross-server-privesc](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/05-cross-server-privesc); [llm-agent-vuln-scan](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan) | Covered |
| [BX 4] Documenting AI Findings, Risk Rating & Remediation Reports | [Security testing (triage and report)](../../02-llm-security/security-testing/README.md); [Rating and managing risks](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/05-rating-and-managing-risks.md); [Report template](../../cmcpse-course/ch5-devsecops-for-mcp-security/report-template.md) | [risk-rating](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating); [redteam-release-gate](../../caase-course/ch6-operationalizing-agentic-ai-security/labs/redteam-release-gate) | Covered |

## Day-by-day plan

- Day 16: red-team methodology, rules of engagement, ATLAS mapping lab.
- Day 17: multi-turn (Crescendo-style) and encoding evasion; jailbreak lab.
- Day 18: indirect injection through documents, web pages and email.
- Day 19: NEW garak/PyRIT-style scanner lab.
- Day 20: run real garak/PyRIT against a local model (guide), compare with the lab.
- Day 21: agentic workflows and privilege escalation paths.
- Day 22: write findings with risk ratings and remediation; release-gate lab.

## Interview / exam questions

<details><summary><b>How is an AI red-team finding different from a classic pentest finding?</b></summary>

It is probabilistic: report the success rate over N runs, the exact prompt/context, model and version, and the impact path (what the injected instruction made the system do), not just 'it worked once'.

</details>

<details><summary><b>garak vs PyRIT in one sentence each?</b></summary>

garak is a scanner: many probe families against a model with detectors and a report. PyRIT is a framework for building targeted (often multi-turn) attacks with converters, scorers and memory.

</details>

<details><summary><b>Why map findings to MITRE ATLAS?</b></summary>

It gives a shared vocabulary with the SOC and threat intel, links findings to detections and mitigations, and shows coverage gaps.

</details>

---

Previous: [Module 03](../m03-llm-vulnerabilities-owasp/README.md) · [Course home](../README.md) · Next: [Module 05](../m05-guardrails-defenses-and-governance/README.md)
