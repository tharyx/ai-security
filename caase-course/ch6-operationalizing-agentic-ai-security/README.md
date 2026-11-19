# Chapter 6: Operationalizing Agentic AI Security

> **Time:** ~24 hours. **You will:** gate agent releases with red-team suites, trace and monitor agent behavior, build a defensive triage agent, vet harnesses, models and marketplaces, produce and sign an AIBOM, and map your work to NIST, OWASP ASI, zero trust, the EU AI Act, confidential computing and the CISA Five Eyes guidance. Every lab is offline and tested.

## Syllabus coverage

Every syllabus line of the chapter, in course order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| SAST/DAST and Testing Gates for Agentic Pipelines | [01 Testing gates and CI/CD](01-testing-gates-and-cicd-for-agents.md); repo: [06 cicd](../../06-ai-devsecops/cicd/README.md), [02 security-testing](../../02-llm-security/security-testing/README.md) | n/a |
| &nbsp;&nbsp;SAST/DAST adapted for agent code and harness configurations | [01, section 2.1](01-testing-gates-and-cicd-for-agents.md#21-sast-and-dast-adapted-for-agents); [cmcpse ch5 SAST lab](../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md) | harness-config checks in [redteam-release-gate](labs/redteam-release-gate/README.md) |
| &nbsp;&nbsp;Red-teaming and adversarial testing gates before agent release | [01, section 2.2](01-testing-gates-and-cicd-for-agents.md#22-red-team-and-adversarial-gates-before-release) | [redteam-release-gate](labs/redteam-release-gate/README.md) |
| CI/CD Integration for Agentic Security | [01, section 2.3](01-testing-gates-and-cicd-for-agents.md#23-cicd-integration-for-agentic-security) ([SVG](../../images/caase-ch6-release-pipeline.svg)); repo: [06 cicd](../../06-ai-devsecops/cicd/README.md), [cmcpse ch5](../../cmcpse-course/ch5-devsecops-for-mcp-security/README.md) | CI snippet and exit codes in [redteam-release-gate](labs/redteam-release-gate/README.md) |
| Observability and Anomaly Detection for Agent Behavior | [02 Observability and anomaly detection](02-observability-and-anomaly-detection.md); repo: [05 monitoring-and-response](../../05-agent-security/monitoring-and-response/README.md) | n/a |
| &nbsp;&nbsp;Observability for autonomous decision-making | [02, section 2.1](02-observability-and-anomaly-detection.md#21-observability-for-autonomous-decision-making) ([SVG](../../images/caase-ch6-observability.svg)) | [agent-observability-dashboard](labs/agent-observability-dashboard/README.md) |
| &nbsp;&nbsp;Anomaly detection for agent behavior drift | [02, section 2.2](02-observability-and-anomaly-detection.md#22-anomaly-detection-for-behavior-drift) | [agent-observability-dashboard](labs/agent-observability-dashboard/README.md) |
| Agentic AI for Defensive SecOps | [03 Defensive SecOps agents](03-defensive-secops-agents.md); repo: [10-capstone lesson 05](../../10-capstone-project/05-ai-soc-monitoring-extension.md), [09 lesson 08](../../09-enterprise-architecture/08-continuous-assessment-and-ai-secops.md) | [secops-triage-agent](labs/secops-triage-agent/README.md) |
| Vetting Third-Party Harnesses, Models, and Marketplaces | [04 Vetting harnesses, models and marketplaces](04-vetting-harnesses-models-and-marketplaces.md); repo: [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) | n/a |
| &nbsp;&nbsp;Vetting third-party harnesses, orchestration frameworks, and open/free models | [04, section 2.1](04-vetting-harnesses-models-and-marketplaces.md#21-vetting-harnesses-orchestration-frameworks-and-open-or-free-models) | [model-provenance-vetting](labs/model-provenance-vetting/README.md) |
| &nbsp;&nbsp;Vetting community skill/plugin marketplaces before installation | [04, section 2.2](04-vetting-harnesses-models-and-marketplaces.md#22-vetting-community-skill-and-plugin-marketplaces); [cmcpse ch6 lesson 02](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/02-vetting-third-party-mcp-servers.md) | [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md) |
| AI/Agent Bill of Materials and Provenance Tracking | [05 AIBOM, provenance and signing](05-aibom-provenance-and-signing.md); repo: [CAISP ch6 lesson 04](../../caisp-course/ch6-supply-chain-attacks-in-ai/04-transparency-and-integrity-sbom-mlbom-signing.md) | [aibom-harness](labs/aibom-harness/README.md), [sign-verify-harness](labs/sign-verify-harness/README.md) |
| Governance, Compliance, and Emerging Frontiers | [06](06-nist-ai-rmf-asi-controls-and-zero-trust.md), [07](07-eu-ai-act-and-comparable-frameworks.md), [08](08-confidential-computing-and-attestation.md), [09](09-cisa-five-eyes-agentic-ai-guidance.md); repo: [07-ai-governance](../../07-ai-governance/README.md), [08-ai-compliance](../../08-ai-compliance/README.md) | n/a |
| &nbsp;&nbsp;NIST AI RMF and OWASP Agentic Security Initiative controls in practice | [06, sections 2.1 and 2.2](06-nist-ai-rmf-asi-controls-and-zero-trust.md#21-nist-ai-rmf-in-practice) | fill the ASI control matrix (exercise in 06) |
| &nbsp;&nbsp;Zero Trust patterns applied to autonomous agents | [06, section 2.3](06-nist-ai-rmf-asi-controls-and-zero-trust.md#23-zero-trust-patterns-for-autonomous-agents); repo: [09 lesson 07](../../09-enterprise-architecture/07-centralized-ai-iam-and-zero-trust.md) | zero-trust redraw exercise in 06 |
| &nbsp;&nbsp;EU AI Act and comparable frameworks for autonomous systems | [07](07-eu-ai-act-and-comparable-frameworks.md); repo: [08-ai-compliance lesson 01](../../08-ai-compliance/01-eu-ai-act.md) | classification exercise in 07 |
| &nbsp;&nbsp;Confidential computing and attestation for agent execution | [08](08-confidential-computing-and-attestation.md) ([SVG](../../images/caase-ch6-attestation-flow.svg)) | thought exercise in 08 (twin idea: [sign-verify-harness](labs/sign-verify-harness/README.md)) |
| &nbsp;&nbsp;CISA Five Eyes Agentic AI Security Guidance | [09](09-cisa-five-eyes-agentic-ai-guidance.md) ([SVG](../../images/caase-ch6-cisa-guidance-map.svg)) | category-to-lab mapping table in 09 |
| Hands-on Exercises: | see the lab index below | |
| &nbsp;&nbsp;Gating Agent Releases with a Red-Team Test Suite in CI/CD | [01](01-testing-gates-and-cicd-for-agents.md) | [redteam-release-gate](labs/redteam-release-gate/README.md) |
| &nbsp;&nbsp;Building an Observability Dashboard for Agent Reasoning Traces | [02](02-observability-and-anomaly-detection.md) | [agent-observability-dashboard](labs/agent-observability-dashboard/README.md) |
| &nbsp;&nbsp;Generating an AI/Agent Bill of Materials (AIBOM) for a Harness | [05](05-aibom-provenance-and-signing.md) | [aibom-harness](labs/aibom-harness/README.md) |
| &nbsp;&nbsp;Vetting an Open-Weight Model's Provenance Before Routing Production Traffic to It | [04](04-vetting-harnesses-models-and-marketplaces.md) | [model-provenance-vetting](labs/model-provenance-vetting/README.md) |
| &nbsp;&nbsp;Signing and Verifying an Agent Harness Using Cosign | [05](05-aibom-provenance-and-signing.md) | [sign-verify-harness](labs/sign-verify-harness/README.md) (HMAC twin + hedged real cosign) |
| &nbsp;&nbsp;Scanning Marketplace Skills for Supply-Chain Risk | [04](04-vetting-harnesses-models-and-marketplaces.md) | [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md); single-skill lab: [chapter 4 skill-vetting](../ch4-computer-use-browser-and-coding-agents/labs/skill-vetting) |
| &nbsp;&nbsp;Building a Defensive SecOps Agent for Alert Triage | [03](03-defensive-secops-agents.md) | [secops-triage-agent](labs/secops-triage-agent/README.md) |

## Lab index

| Lab | Course exercise | Offline | Tests | What it proves |
|---|---|---|---|---|
| [redteam-release-gate](labs/redteam-release-gate/README.md) | Red-team gate in CI/CD | yes | 8 | Critical success or high ASR breaks the build; suite cannot shrink |
| [agent-observability-dashboard](labs/agent-observability-dashboard/README.md) | Trace dashboard + drift | yes | 8 | Baseline drift rules; escaped HTML/Markdown dashboard |
| [aibom-harness](labs/aibom-harness/README.md) | AIBOM for a harness | yes | 7 | CycloneDX-style output, validation, diff |
| [model-provenance-vetting](labs/model-provenance-vetting/README.md) | Open-weight model vetting | yes | 11 | Hashes, format, org, licence, evals give a routing decision |
| [sign-verify-harness](labs/sign-verify-harness/README.md) | Sign/verify with cosign | yes (+ hedged real cosign) | 9 | Modified, missing, extra files and forged signatures are rejected |
| [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md) | Scan marketplace skills | yes | 9 | Batch scoring and reports; no misses or false positives on planted set |
| [secops-triage-agent](labs/secops-triage-agent/README.md) | Defensive SecOps agent | yes | 10 | Injection-resistant triage; deterministic verdict; ATT&CK notes |

Run all of them:

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security -v
```

## Outdated in the syllabus -> current

| Syllabus says | Current (Nov 2026; verify at source) |
|---|---|
| "CISA Five Eyes Agentic AI Security Guidance" | Published **1 May 2026** as **"Careful Adoption of Agentic AI Services"** by CISA, NSA and the Australian, Canadian, New Zealand and UK cyber agencies. Risk categories as reported: privilege, design/configuration, behavioral, structural, accountability (some sources add supply chain). |
| EU AI Act dates | **Digital Omnibus**, Regulation (EU) 2026/1744 (in force 27 Jul 2026): stand-alone high-risk from **2 Dec 2027**, embedded from **2 Aug 2028**; GPAI obligations since **2 Aug 2025**. |
| "OWASP ASI controls" | The **Top 10 for Agentic Applications 2026 (ASI01 to ASI10)** plus "Agentic AI: Threats and Mitigations". An OWASP "Agent Control Standard" is mentioned in 2026 research notes: hedge. |
| NIST AI RMF | AI RMF 1.0 + **GenAI Profile (AI 600-1)**; adversarial taxonomy **AI 100-2 E2025**; **AI Agent Standards Initiative** (Feb 2026, verify). |
| Cosign | Cosign and Sigstore support **keyless** signing with CI identity and bundles; flags change between versions. Check the docs. |
| Marketplaces and harnesses | Real incidents now exist (ClawHavoc on ClawHub, OpenClaw exposure and CVE-2026-25253, postmark-mcp). Hardened spin-offs (NemoClaw, NanoClaw, SecureClaw, MiniClaw) exist; hedge details. |
| Confidential computing | TEE support now includes confidential VMs (Intel TDX, AMD SEV-SNP) and confidential GPUs; verify per vendor. |

## Learning order

1. [01](01-testing-gates-and-cicd-for-agents.md) and [redteam-release-gate](labs/redteam-release-gate/README.md).
2. [02](02-observability-and-anomaly-detection.md) and [agent-observability-dashboard](labs/agent-observability-dashboard/README.md).
3. [03](03-defensive-secops-agents.md) and [secops-triage-agent](labs/secops-triage-agent/README.md).
4. [04](04-vetting-harnesses-models-and-marketplaces.md), then [model-provenance-vetting](labs/model-provenance-vetting/README.md) and [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md).
5. [05](05-aibom-provenance-and-signing.md), then [aibom-harness](labs/aibom-harness/README.md) and [sign-verify-harness](labs/sign-verify-harness/README.md).
6. [06](06-nist-ai-rmf-asi-controls-and-zero-trust.md), [07](07-eu-ai-act-and-comparable-frameworks.md), [08](08-confidential-computing-and-attestation.md), [09](09-cisa-five-eyes-agentic-ai-guidance.md).
7. The Q&As below.

## Exam tips for this chapter

- **Gate anatomy:** category coverage, severity-weighted thresholds, impact-based assertions, benign controls, minimum suite size; fail closed.
- **SAST for agents** includes prompts, tool descriptions, skills and MCP lists, not only code.
- **Drift signals:** new tool, tool-mix shift (TVD), step outliers, new decision values. Re-baseline after approved changes.
- **SecOps agent rule:** the model explains; deterministic code decides; humans contain. Alert text is untrusted.
- **Vetting models:** hashes, safetensors vs pickle, licence, org, evals, then route (production / sandbox / reject).
- **AIBOM contents:** model, tools (with description hash), MCP servers, skills, prompts, libraries, relationships.
- **Signing:** verify signature, trusted key, then re-hash everything including extra files. HMAC is symmetric.
- **Dates:** EU AI Act Omnibus 2 Dec 2027 (stand-alone high-risk) and 2 Aug 2028 (embedded). CISA guidance 1 May 2026.
- **Attestation proves what runs, not that it behaves.**

## 15 exam-style questions

<details><summary>1. How do you adapt SAST and DAST for agents?</summary>

SAST scans code plus harness configuration: tool definitions and descriptions, prompts, skills, MCP lists, permissions, dependencies and secrets. DAST attacks the running agent through every untrusted channel and asserts on impact such as forbidden tool calls or leaked canaries.
</details>

<details><summary>2. What makes a red-team release gate trustworthy?</summary>

Category coverage, severity-weighted thresholds, impact-based checks, fresh agent per attack, benign controls, a minimum suite size, versioned results and reviewed changes to the suite and thresholds.
</details>

<details><summary>3. Why report attack success rate (ASR)?</summary>

Model behavior varies across runs. Repeating attacks and tracking ASR shows regressions and trends that one pass hides.
</details>

<details><summary>4. What belongs in an agent trace?</summary>

Plan steps, model calls, tool calls with redacted or hashed arguments, decisions, identity and delegation chain, timing and cost. Redact secrets and store off-host.
</details>

<details><summary>5. How do you detect behavior drift?</summary>

Compare a window to a baseline: new tools, tool-mix distance, step-count outliers, unseen decisions, rate and destination changes. Respond, and re-baseline after approved changes.
</details>

<details><summary>6. Why must a trace dashboard escape its data?</summary>

Trace content includes attacker-controlled text. Unescaped HTML can run in an analyst's browser, and unfiltered text can inject an AI that reads it.
</details>

<details><summary>7. What may a SecOps triage agent do autonomously?</summary>

Read-only enrichment, summarization, ATT&CK mapping, notes, priority suggestions and queueing for humans. Closing alerts, containment and rule changes need human approval.
</details>

<details><summary>8. How is the lab's triage agent injection-resistant?</summary>

Deterministic verdict from facts, injection detected as a signal, text neutralized and truncated before the model, model output never executed, actions allowlisted, humans approve containment.
</details>

<details><summary>9. How do you vet an open-weight model for production routing?</summary>

Verify the publisher and hashes, require a safe format, review the licence, read the model card and data disclosure, run your own injection and safety evals, route to production, sandbox or reject, and record the result in the AIBOM.
</details>

<details><summary>10. How do you vet a skill marketplace entry?</summary>

Scan for download-and-execute, credential access, unknown domains, obfuscation, injected instructions, typosquats and excess permissions; review flagged items; pin by hash; sandbox with least privilege; monitor updates for rug pulls.
</details>

<details><summary>11. What is an AIBOM and what does it add over an SBOM?</summary>

A bill of materials that also lists models, datasets, prompts, tools, MCP servers and skills with versions and hashes. It answers "which agents use X?" and detects silent behavior-defining changes.
</details>

<details><summary>12. How do you sign and verify a harness, and why is the HMAC lab only a twin?</summary>

Sign a canonical manifest (for example `cosign sign-blob`), verify signature and trusted key, then re-hash all files and reject modified, missing or extra ones. HMAC is symmetric, so verifiers could forge; cosign uses asymmetric or keyless identity.
</details>

<details><summary>13. Give two zero-trust principles applied to agents.</summary>

Verify every agent, tool and message explicitly with short-lived scoped credentials; assume breach, isolate agents and keep a kill switch. Also enforce policy centrally at a gateway and re-evaluate behavior continuously.
</details>

<details><summary>14. What are the EU AI Act dates after the Digital Omnibus?</summary>

As reported: stand-alone high-risk systems from 2 December 2027, embedded from 2 August 2028 (Regulation (EU) 2026/1744, in force 27 July 2026); GPAI obligations since 2 August 2025. Verify at EUR-Lex.
</details>

<details><summary>15. Summarize the CISA Five Eyes "Careful Adoption of Agentic AI Services" guidance and what attestation adds.</summary>

Published 1 May 2026, it recommends careful, scoped adoption across risk categories such as privilege, design/configuration, behavioral, structural and accountability (verify the list), with least privilege, human oversight, testing, monitoring and incident readiness. Attestation adds proof of what code runs in a TEE and gates secret release, but does not fix agent behavior risks.
</details>

## References

- Lessons 01 to 09 in this folder.
- CISA and partners, "Careful Adoption of Agentic AI Services" (1 May 2026): verify at source.
- NIST AI RMF 1.0, AI 600-1, AI 100-2 E2025, SP 800-207; OWASP Top 10 for Agentic Applications 2026.
- EU AI Act (Reg. (EU) 2024/1689) and Reg. (EU) 2026/1744 on EUR-Lex.
- CycloneDX, SPDX, SLSA, Sigstore/cosign documentation; Confidential Computing Consortium; IETF RFC 9334.
- Previous: [Chapter 5](../ch5-multi-agent-systems-and-agent-identity/README.md). Next: [Chapter 7](../ch7-threat-modeling-agents-and-communication-protocols/README.md).
