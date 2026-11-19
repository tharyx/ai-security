# Module 06: AI Security Monitoring & SOC Fundamentals (days 30–35)

What to log in LLM, agent and MCP systems, how to turn it into detections and risk scores, and how a SOC responds to AI incidents with SIEM alerts and SOAR playbooks. This module matches your SOC day job.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 6] AI Security Telemetry, Audit Trails & Detection Events | [Agent monitoring and response](../../05-agent-security/monitoring-and-response/README.md); [MCP logging and detection](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/06-logging-monitoring-detection.md); [Runtime security](../../06-ai-devsecops/runtime-security/README.md) | [monitoring lab](../../05-agent-security/monitoring-and-response/lab); [tool-invocation-logging](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging) | Covered |
| [BX 6] What to Log in LLM Applications (prompts, responses, tool calls, latency) | [What to log](../../05-agent-security/monitoring-and-response/README.md); [Logging without a new leak](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md) | [runtime-security lab](../../06-ai-devsecops/runtime-security/lab); [agent-observability-dashboard](../../caase-course/ch6-operationalizing-agentic-ai-security/labs/agent-observability-dashboard) | Covered |
| [BX 6] User, Session & Request Behavior Monitoring | [Baselines plus rules](../../05-agent-security/monitoring-and-response/README.md); [Runtime security](../../06-ai-devsecops/runtime-security/README.md) | [runtime-security lab (per-principal baseline)](../../06-ai-devsecops/runtime-security/lab); **NEW** [ai-soar-playbooks](labs/ai-soar-playbooks) | Covered |
| [BX 6] Risk Scoring, Drift & Anomaly Detection | [Observability and anomaly detection](../../caase-course/ch6-operationalizing-agentic-ai-security/02-observability-and-anomaly-detection.md); [AI SOC monitoring extension](../../10-capstone-project/05-ai-soc-monitoring-extension.md) | [06-objective-drift-detection](../../caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/06-objective-drift-detection); **NEW** [ai-soar-playbooks (risk scoring)](labs/ai-soar-playbooks) | Covered |
| [BX 6] SIEM/SOAR Alerting & AI Incident Response Lifecycle | [Red team and incident exercise](../../10-capstone-project/03-red-team-and-incident-exercise.md); [AI incidents](../../07-ai-governance/06-model-approval-lifecycle-and-ai-incidents.md); [SIEM concepts](../../cybersecurity-track/06-siem-sentinel-splunk/01-siem-concepts.md); **NEW** [Sentinel and Splunk AI detections](real-tools/sentinel-splunk-ai-detections.md) | **NEW** [ai-soar-playbooks](labs/ai-soar-playbooks); [incident drill](../../10-capstone-project/lab) | Gap filled here |
| [BX 6] Real-World AI Security SOC Scenarios & Investigation Use Cases | [AI SOC monitoring extension](../../10-capstone-project/05-ai-soc-monitoring-extension.md); [Defensive SecOps agents](../../caase-course/ch6-operationalizing-agentic-ai-security/03-defensive-secops-agents.md); [Alert triage](../../cybersecurity-track/05-soc-fundamentals/02-alert-triage.md) | [soc_triage lab](../../10-capstone-project/lab); [secops-triage-agent](../../caase-course/ch6-operationalizing-agentic-ai-security/labs/secops-triage-agent) | Covered |

## Day-by-day plan

- Day 30: AI telemetry and audit trails; what to log and what never to log.
- Day 31: user, session and request behaviour monitoring; runtime-security lab.
- Day 32: risk scoring, drift and anomaly detection.
- Day 33: NEW AI SOAR playbooks lab (detections → incidents → playbooks).
- Day 34: write the same detections in KQL and SPL (guide); test in your SIEM if you have access.
- Day 35: SOC investigation scenarios; triage lab and an incident write-up.

## Interview / exam questions

<details><summary><b>Which fields should every LLM request log carry for investigations?</b></summary>

Timestamp, user/session/tenant, request ID, model and version, prompt and response hashes or redacted text, guardrail verdicts, retrieved document IDs, tool calls with arguments and results, tokens and latency.

</details>

<details><summary><b>First three containment steps for an indirect prompt injection that triggered data exfiltration?</b></summary>

Revoke the agent's tokens or disable the abused tool, quarantine the poisoned source and re-index, and preserve evidence (prompts, retrieved docs, tool-call logs) before cleanup.

</details>

<details><summary><b>Why should destructive SOAR steps need approval?</b></summary>

False positives are common in AI detections; automatic token revocation or tool disablement can cause outages, so gate high-impact actions with a human approval step.

</details>

---

Previous: [Module 05](../m05-guardrails-defenses-and-governance/README.md) · [Course home](../README.md) · Next: [Module 07](../m07-mcp-security-fundamentals/README.md)
