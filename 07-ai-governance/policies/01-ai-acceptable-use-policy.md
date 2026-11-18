# AI Acceptable Use Policy

| Field | Value |
|---|---|
| Policy ID | POL-AI-01 |
| Version | 1.0 |
| Owner | Head of AI Governance |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-05-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Let staff use AI tools productively without leaking data, breaking the law or handing decisions about people to a machine. This is the one AI policy every employee reads, so it is short.

## 2. Scope

All employees, contractors and interns, on any device used for work. It covers chat assistants, coding assistants, AI features inside SaaS products, browser extensions, agents and AI APIs. It does not cover *building* AI systems: that is the [AI Model Approval Policy](03-ai-model-approval-policy.md) and the [AI Security Standard](07-ai-security-standard.md).

## 3. Roles

| Role | Responsibility |
|---|---|
| Every user | Follows this policy; is accountable for any AI output they use or send |
| Line manager | Makes sure the team is trained; approves use cases inside the team |
| AI Governance Office | Keeps the approved-tool list; answers questions; handles exceptions |
| Security | Runs the technical controls (proxy, DLP, SSO, extension allowlist) |
| HR | Includes the policy in onboarding; handles breaches |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| AUP-01 | Use only AI tools on the approved-tool list, signed in with your work (SSO) account. | Proxy and CASB reports of AI domains; shadow-AI discovery report (lab `discover_shadow_ai`) |
| AUP-02 | Follow the data table: public data in any approved tool; internal data in approved enterprise tools; confidential, personal or customer data only in tools approved for that data class; secrets and credentials never. | DLP alerts on AI domains; quarterly DLP rule test |
| AUP-03 | Check AI output before you use it: facts, numbers, citations, code and legal text. You own the result. | Spot checks in code review and content review; incident records |
| AUP-04 | Do not use AI to make or materially shape decisions about people (hiring, pay, performance, credit, access to services) unless that AI system is registered and approved for that use. | AI system register; release gate refuses unregistered systems |
| AUP-05 | Do not use AI for prohibited purposes: deceiving people, impersonating a real person, sexual or harassing content, surveillance of colleagues, or anything on the prohibited-use list. | Prohibited-use list in the register (GOV-07); HR case records |
| AUP-06 | Tell people when they deal with AI: label AI-generated content you publish externally, and never present an AI chatbot as a human. | Content review checklist; disclosure check (lab TR-01, TR-02) |
| AUP-07 | Do not connect AI agents, browser extensions or plugins to work email, files or code repositories unless the tool is approved for that access. | OAuth consent report; extension allowlist report |
| AUP-08 | Report AI mistakes, leaks or strange behaviour (for example an assistant following instructions hidden in a document) to security within one working day. | Incident tickets tagged AI; time-to-report metric |
| AUP-09 | Complete AI literacy training when you join and every year. | Training completion report (target 95%) |

## 5. Exceptions

Ask the AI Governance Office. Exceptions are approved by the policy owner, recorded in the register, time-limited (maximum 6 months) and reported. The secrets rule in AUP-02 and all of AUP-05 cannot be waived.

## 6. Review cycle

Every 6 months (AI tools change fast), and early after a serious AI incident, a new law or regulator guidance, or a new class of tool such as agents. Repeated exceptions to the same rule are a review trigger: the rule may be wrong.

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| AUP-01, AUP-07 | GOVERN 1.6 (inventory), GOVERN 6.1 | Annex A.9 (use of AI systems) | OWASP LLM02:2026 Sensitive Information Disclosure |
| AUP-02 | MAP 4.1, MEASURE 2.10 | Annex A.7 (data for AI systems) | GDPR Art 5 and 32; India DPDP Act s.8 |
| AUP-03, AUP-04 | GOVERN 3.2, MAP 3.5 | Annex A.9 | EU AI Act Art 14 and 26 |
| AUP-05 | GOVERN 1.1 | Clause 5.2 (AI policy), Annex A.2 | EU AI Act Art 5 |
| AUP-06 | MEASURE 2.8 | Annex A.8 (information for interested parties) | EU AI Act Art 50 |
| AUP-08 | GOVERN 4.3, MANAGE 4.3 | Annex A.3 (internal organization, reporting concerns) | |
| AUP-09 | GOVERN 2.2 | Clause 7.2, 7.3 (competence, awareness) | EU AI Act Art 4 |
