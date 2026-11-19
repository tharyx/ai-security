# 04: Threat Modeling and Risk Frameworks for Agentic AI

> **Chapter:** 1 · Agents, Harnesses and the Agentic Ecosystem · **Time:** ~4 hours
> **You will:** use OWASP LLM Top 10 (2026), the OWASP Agentic Security Initiative list (ASI01 to ASI10), MITRE ATLAS, the NIST AI RMF and NIST AI 100-2 E2025 to describe agent risks, and rate agentic risks with factors that matter for agents: autonomy, reversibility, blast radius, privileges and data sensitivity.

| | |
|---|---|
| **Prerequisites** | [Lesson 03](03-agentic-attack-surface.md); [CAISP chapter 5, threat modeling](../../caisp-course/ch5-threat-modeling-ai-systems/README.md) |
| **Lab** | [`labs/atlas-threat-model-agent`](labs/atlas-threat-model-agent/): YAML system description to ATLAS tactics, ASI items and risk ratings, with tests |
| **Syllabus lines** | Threat Modeling and Risk Frameworks for Agentic AI · OWASP Top 10 for LLM Applications · OWASP Agentic Security Initiative · MITRE ATLAS matrix for AI/ML systems · NIST AI Risk Management Framework (AI RMF) · NIST AI 100-2 adversarial ML taxonomy · Rating agentic-specific risks |
| **Existing repo lessons to reuse** | [OWASP LLM 2023 vs 2026](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md) · [ATT&CK vs ATLAS and the 14 tactics](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md) · [Rating and managing risks](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md) · [AI risk management (NIST AI RMF)](../../07-ai-governance/03-ai-risk-management.md) · [05-agent-security ASI mapping](../../05-agent-security/README.md) |

> **Verify at source.** Lists and taxonomies are updated often. This lesson gives names and ideas as of late 2026. Check the live sources named in each section.

---

## 1. Why this matters

A framework is a shared vocabulary. When you say "ASI03 on the mail tool, ATLAS Exfiltration, rated high because the action is irreversible and the agent is at autonomy level 3", every security person understands the claim. In an exam, you must name the items. In a job, you must pick the right framework for the job and not mix them up.

| Framework | Answers the question | Use it to |
|---|---|---|
| OWASP LLM Top 10 | What goes wrong in an LLM application? | Review app design and code |
| OWASP Agentic (ASI) | What goes wrong when the system acts? | Review agent design, autonomy, tools, memory, identity |
| MITRE ATLAS | How do attackers behave against AI systems? | Red team planning, detection coverage, incident reports |
| NIST AI RMF | How does an organization govern AI risk? | Program and process (Govern, Map, Measure, Manage) |
| NIST AI 100-2 | What is the vocabulary of attacks on AI? | Classify attacks precisely |
| Your rating method | Which risk first? | Prioritize work |

## 2. Understand it

### 2.1 OWASP Top 10 for LLM Applications (2026 list)

The course may still show the 2023 names (LLM01 Prompt Injection, LLM02 Insecure Output Handling, and so on). The current list (2026, as our notes have it; verify at <https://genai.owasp.org>) is:

| 2026 | Name | Agent angle |
|---|---|---|
| LLM01 | Prompt Injection | The trigger for most agent incidents; indirect injection through observations |
| LLM02 | Sensitive Information Disclosure | Secrets in prompts, logs and reasoning traces; data sent to cloud routers |
| LLM03 | Excessive Agency | Too many tools, too much permission, too much autonomy: the core agent risk |
| LLM04 | Supply Chain | Models, skills, plugins, MCP servers, packages |
| LLM05 | Data and Model Poisoning | Poisoned memory and retrieval stores; tampered models |
| LLM06 | Unbounded Consumption | Runaway loops, cost attacks (budgets) |
| LLM07 | Misinformation | Wrong output acted on automatically |
| LLM08 | Hidden Context Exposure | System prompts, hidden instructions and memory leaking |
| LLM09 | Vector and Embedding Weaknesses | RAG memory stores |
| LLM10 | Improper Output Handling | Model output executed as code or commands |

Mapping notes: Insecure Plugin Design (2023) folded into Excessive Agency and Improper Output Handling, and today maps to tool and MCP security; Overreliance became Misinformation; Model DoS became Unbounded Consumption; Model Theft is covered elsewhere. Full comparison: [OWASP LLM 2023 vs 2026](../../caisp-course/ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md).

### 2.2 OWASP Agentic Security Initiative (ASI)

The **Agentic Security Initiative** works under the OWASP GenAI Security Project. It produced "Agentic AI: Threats and Mitigations" and the **OWASP Top 10 for Agentic Applications 2026** (ASI01 to ASI10, published around December 2025; verify the current text). Some of the project's notes also mention an **Agent Control Standard** donated to OWASP in 2026 (hedge; check the project page).

| ID | Risk | One line | Where in this course |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Injected content redirects what the agent is trying to do | Ch 2 |
| ASI02 | Tool Misuse and Exploitation | A real tool used in an unsafe way (right tool, wrong target) | Ch 3 |
| ASI03 | Identity and Privilege Abuse | Shared, inherited or over-broad credentials; confused deputy | Ch 5 |
| ASI04 | Agentic Supply Chain Vulnerabilities | Malicious skills, servers, agent cards, models | Ch 1, 5 |
| ASI05 | Unexpected Code Execution | Generated code runs with real power | Ch 4 |
| ASI06 | Memory and Context Poisoning | Hostile content persists in memory and context | Ch 3 |
| ASI07 | Insecure Inter-Agent Communication | Forged, replayed or spoofed agent messages | Ch 5, 7 |
| ASI08 | Cascading Failures | One failure spreads across agents or steps | Ch 5, 6 |
| ASI09 | Human-Agent Trust Exploitation | Agents persuade people to approve harmful actions | Ch 2, 6 |
| ASI10 | Rogue Agents | An agent drifts or is compromised and keeps acting | Ch 6 |

Every item has a lab test in [05-agent-security](../../05-agent-security/README.md) that checks the **impact** (money moved, mail sent, rule changed), not the model's wording.

### 2.3 MITRE ATLAS for AI/ML systems

ATLAS has the same structure as ATT&CK: tactics (the attacker's goal), techniques (how), case studies, mitigations. The course lists 14 tactics: Reconnaissance, Resource Development, Initial Access, ML Model Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Collection, ML Attack Staging, Exfiltration, Impact.

> **Outdated in the syllabus?** ATLAS has about 16 tactics in 2026 (the 14 above adapted from ATT&CK plus AI-specific ones), and renamed "ML Model Access" to **"AI Model Access"** and "ML Attack Staging" to **"AI Attack Staging"** (data version 2026.07; secondary sources report a further rename to "AI Attack Adaptation", unconfirmed). Tactic IDs differ between sources. Use the course names for the exam and the live matrix at <https://atlas.mitre.org> for real reports. Full lesson: [ATT&CK vs ATLAS and the 14 tactics](../../caisp-course/ch2-understanding-and-attacking-llms/02-attck-vs-atlas-and-the-14-tactics.md).

Agent reading of the tactics:

| Tactic | In an agentic system |
|---|---|
| Reconnaissance | Learn which agent, model, tools and gateway exist (exposed ports, public skill lists) |
| Resource Development | Publish a malicious skill or MCP server; register a typosquat domain |
| Initial Access | A prompt injection in an email or web page; a compromised skill |
| ML (AI) Model Access | Reach the model through the agent's own interface to probe it |
| Execution | The agent runs the attacker's tool call or code |
| Persistence | Poison memory or notes; add a scheduled task or a skill |
| Privilege Escalation | Use the agent's broader credentials than the user has |
| Defense Evasion | Hide instructions; make the agent skip approval or logging |
| Credential Access | Read tokens from config files, environment, memory |
| Discovery | Make the agent list files, tools, other agents |
| Collection | Gather data through the agent's read tools |
| ML (AI) Attack Staging | Build proxy models, craft the adversarial content |
| Exfiltration | Send data out through an allowed tool (mail, web, DNS) |
| Impact | Delete data, spend money, send harmful messages, disrupt service |

### 2.4 NIST AI Risk Management Framework (AI RMF)

NIST **AI RMF 1.0** (AI 100-1, January 2023) is a voluntary framework with four functions: **Govern** (policies, roles, culture), **Map** (context and risks), **Measure** (test and track), **Manage** (treat and respond). The **Generative AI Profile (NIST AI 600-1, July 2024)** lists risks specific to generative AI and suggested actions. NIST also announced an **AI Agent Standards Initiative** in early 2026 (hedge; verify the current scope).

| Function | Agent example |
|---|---|
| Govern | An inventory of agents and owners; a rule that no agent gets production write access without review |
| Map | The pipeline and trust boundaries from [lesson 03](03-agentic-attack-surface.md); who is affected |
| Measure | Red team tests, tool-call validity rates, incident metrics |
| Manage | Approvals, kill switch, incident runbooks, retiring agents |

"RMF" without "AI" often means NIST SP 800-37 (Risk Management Framework for systems); do not confuse them. See [AI risk management](../../07-ai-governance/03-ai-risk-management.md).

Also relevant (hedged): the joint guidance **"Careful Adoption of Agentic AI Services"**, published on 1 May 2026 by CISA with partners (NSA, Australia's ACSC, the Canadian Cyber Centre, New Zealand's NCSC and the UK NCSC), described as the first joint Five Eyes guidance on agentic AI. Summaries group risks into categories such as privilege, design and configuration, behavioral, structural and accountability (some sources list supply chain instead). Verify the title, categories and page count at the agencies' sites.

### 2.5 NIST AI 100-2 adversarial machine learning taxonomy

**NIST AI 100-2 E2025**, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations" (March 2025), organizes attacks along **five dimensions**:

1. **AI system type:** predictive AI or generative AI (and agents inside GenAI).
2. **Learning or lifecycle stage** at which the attack happens (training, deployment, and so on).
3. **Attacker goals and objectives:** availability breakdown, integrity violation, privacy compromise (and misuse enablement for GenAI).
4. **Attacker capabilities and access:** what they control (training data, model, queries, resources).
5. **Attacker knowledge:** white box, gray box or black box.

Content in broad strokes: for predictive AI, **evasion**, **poisoning** and **privacy** attacks; for generative AI, additional classes such as **supply chain** attacks, **direct and indirect prompt injection**, **misuse** and, in the 2025 edition, the **security of AI agents**. NIST plans annual updates; we found no 2026 edition (verify at <https://csrc.nist.gov>). The idea for you: when you write "prompt injection", also write the attacker's goal, capability and knowledge, and the lifecycle stage. That is what makes a threat statement precise.

### 2.6 Rating agentic-specific risks

Generic rating is **likelihood times impact** ([CAISP lesson 05](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md)). For agents, impact depends strongly on factors that a chatbot does not have. Score each from 1 (low) to 5 (high):

| Factor | Question | Raises the score |
|---|---|---|
| **Autonomy level** | Does a human approve, or does it act alone? (1 suggest, 2 approve, 3 act then notify, 4 full autonomy) | Higher autonomy |
| **Reversibility** | Can the action be undone (draft vs sent mail; soft delete vs hard delete)? | Irreversible actions |
| **Blast radius** | How many users, systems or records can one action touch? | Wider scope, shared resources |
| **Privileges** | What can the agent's credentials do? Are they shared or per user? | Broad, long-lived, shared credentials |
| **Data sensitivity** | What data is in reach (public to restricted)? | Regulated or secret data |
| **Exposure (likelihood side)** | Does untrusted content reach the model? Is the gateway reachable? Are third-party skills in use? | More untrusted inputs, open entry points |
| **Existing controls (likelihood side)** | Allowlist, approval, sandbox, signing, logging, budgets | Missing controls |

A simple method (used by the [lab](labs/atlas-threat-model-agent/threatmodel.py)): impact is based on the top two of privileges, data sensitivity, blast radius and irreversibility, plus one for autonomy 3 or higher; likelihood starts from exposure and drops by one for each relevant control present; score = likelihood x impact; levels: low under 5, medium 5 to 9, high 10 to 14, critical 15 and above. It is a **decision aid, not a measurement.** The value is the written reasoning. Report inherent risk (before controls) and residual risk (after).

**A finding in report form:**

> ASI02 / ATLAS Exfiltration: the send-mail tool can mail any address; mail is irreversible; the agent runs at autonomy 3 and reads untrusted email. Likelihood 4, impact 5, score 20 (critical). Fix: recipient allowlist, approval for external recipients, per-user scoped token. Residual: likelihood 2, impact 3, score 6 (medium).

## 3. Defend it

- Use **one list for design review (ASI)**, **one for application review (OWASP LLM)**, **ATLAS for adversary stories** and **NIST AI RMF for the program.** Do not try to use every framework for every task.
- Keep a **risk register** ([template](../../00-program/templates/risk-register.csv)) with inherent and residual scores and an owner.
- Re-rate when autonomy, tools or data scope change.
- Tie every critical risk to a control that is tested ([05-agent-security labs](../../05-agent-security/README.md)).

## 4. Hands-on

Run the [atlas-threat-model-agent lab](labs/atlas-threat-model-agent/README.md). Compare the weak and hardened designs. Then write your own YAML for an agent you know and read which ASI items and ATLAS tactics it triggers. Disagree with the tool where you think it is wrong; that is the exercise.

## 5. Scenarios

1. A report says "prompt injection, high". What is missing for an agent? *(Autonomy, reversibility, blast radius, privileges, data sensitivity: what the injection can actually cause.)*
2. A manager asks "which framework should we follow?". *(Use NIST AI RMF for the program, ASI and OWASP LLM for design review, ATLAS for red team and detection; they complement each other.)*
3. Your agent never sends mail, only drafts. How does that change the rating of ASI02? *(Reversibility and autonomy drop: a human sends. Impact drops, though a persuasive draft is still ASI09.)*

## 6. Interview and exam questions

<details><summary><b>Q1. Which OWASP list covers agent-specific risks, and name five items.</b></summary>
The OWASP Top 10 for Agentic Applications 2026 (from the Agentic Security Initiative): ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
</details>

<details><summary><b>Q2. What are the five dimensions in NIST AI 100-2 E2025?</b></summary>
AI system type, lifecycle (learning) stage, attacker goals and objectives, attacker capabilities and access, and attacker knowledge. Use them to describe an attack precisely.
</details>

<details><summary><b>Q3. How is MITRE ATLAS different from ATT&CK, and what changed from the course wording?</b></summary>
ATLAS applies the tactic and technique model to AI systems and adds AI-specific tactics (model access and attack staging). The course's "ML Model Access" and "ML Attack Staging" are now "AI Model Access" and "AI Attack Staging" in current ATLAS data. Check atlas.mitre.org for the current list and IDs.
</details>

<details><summary><b>Q4. Which factors make an agent risk higher than the same risk in a chatbot?</b></summary>
Autonomy, irreversibility of actions, blast radius, privileges of the agent's credentials and the sensitivity of data in reach, together with exposure to untrusted content and missing controls.
</details>

## 7. References

- OWASP GenAI Security Project, LLM Top 10 and the Agentic Security Initiative: <https://genai.owasp.org> (verify).
- MITRE ATLAS: <https://atlas.mitre.org> (verify the version).
- NIST AI RMF 1.0 (AI 100-1) and the Generative AI Profile (AI 600-1): <https://www.nist.gov/itl/ai-risk-management-framework>.
- NIST AI 100-2 E2025, Adversarial Machine Learning taxonomy (March 2025): search at <https://csrc.nist.gov> and verify the edition.
- CISA and partners, "Careful Adoption of Agentic AI Services" (1 May 2026): verify title, date and categories at the agency sites.
- Repo: [CAISP chapter 5](../../caisp-course/ch5-threat-modeling-ai-systems/README.md), [05-agent-security](../../05-agent-security/README.md), [07-ai-governance](../../07-ai-governance/README.md).
