# AI Third-Party Risk Assessment

| Field | Value |
|---|---|
| Policy ID | POL-AI-05 |
| Version | 1.0 |
| Owner | Head of Third-Party Risk |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-11-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Decide, with evidence, whether an AI vendor (model provider, AI SaaS, MCP server, dataset supplier, or a SaaS product that adds AI features) can be trusted with our data and our decisions, and on what contract terms.

## 2. Scope

New AI vendors before contract; existing vendors every year; any vendor that adds AI features to a product we already use. The depth of the review depends on the vendor tier (Appendix B).

## 3. Roles

| Role | Responsibility |
|---|---|
| Business owner | Requests the vendor; answers the use-case questions; owns the residual risk |
| Third-party risk | Runs the questionnaire; scores the answers; tracks reassessment |
| Security | Reviews security answers and reports (SOC 2, ISO/IEC 27001, ISO/IEC 42001, pen tests) |
| Privacy / DPO | Reviews the data processing terms, transfers and sub-processors |
| Legal | Negotiates contract clauses (training use, change notice, incident notice, exit) |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| TPR-01 | Every AI vendor is tiered (Appendix B) before contract, and recorded in the AI system register as a third-party system. | Register entry; tier record |
| TPR-02 | Tier 2 and Tier 3 vendors complete the questionnaire (Appendix A); answers are backed by documents, not only "yes". | Completed questionnaire with attached evidence |
| TPR-03 | The contract states: no training on our data without written consent; retention limit; deletion on request and at exit; regions; sub-processor list and notice of changes. | Signed contract or data processing agreement |
| TPR-04 | The contract requires notice before model or AI-feature changes, and security incident notice within an agreed time (for example 24-72 hours). | Contract clause |
| TPR-05 | The scope of the vendor's certificates and reports is checked: does it cover the AI service we use? | Reviewer note on report scope |
| TPR-06 | For model providers, we receive a model or system card and evaluation results, including safety and security testing. | Vendor documentation in the evidence store |
| TPR-07 | MCP servers and plugins are allowlisted, pinned to a version and reviewed like code before use. | MCP allowlist; review record (see Module 04) |
| TPR-08 | Reassessment: Tier 3 every year, Tier 2 every two years, and immediately after a vendor incident or a major AI feature change. | Assessment dates (evidence older than 365 days is STALE in the Module 08 checker) |
| TPR-09 | High-risk third-party AI has an exit and contingency plan: fallback process, data export, and alternative provider. | Contingency plan document |

## 5. Exceptions

Approved by the CISO and the business owner together, for a maximum of 3 months, with compensating controls (for example no confidential data sent until assessed). TPR-03 training-use clause cannot be waived for personal or confidential data.

## 6. Review cycle

Every year, and when a new type of AI supplier appears (for example agent marketplaces or MCP registries).

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| TPR-01, TPR-02, TPR-05 | GOVERN 6.1, MAP 4.1 | Annex A.10 (third-party and customer relationships) | ISO/IEC 27001 A.5.19 to A.5.22; CERT-In AI audit guideline 8.9 |
| TPR-03, TPR-04 | GOVERN 6.1 | Annex A.10 | GDPR Art 28; DPDP Act s.8(2) |
| TPR-06 | MAP 4.1, MEASURE 2.7 | Annex A.10, A.8 | EU AI Act Art 13 and 53 (information from providers) |
| TPR-07 | MANAGE 3.1 | Annex A.10 | OWASP MCP04 Supply Chain, MCP09 Shadow MCP Servers; OWASP ASI04 |
| TPR-08 | MANAGE 3.1 | Clause 9.1 | |
| TPR-09 | GOVERN 6.2 | Annex A.10 | |

## Appendix A. Vendor questionnaire

Ask for evidence with each answer. "Yes" without a document is "unknown".

| # | Area | Question | Good answer looks like |
|---|---|---|---|
| Q1 | Data use | Do you use our prompts, files or outputs to train or improve any model? Can we opt out by contract? | No training by default; contract clause |
| Q2 | Retention | What do you store (prompts, outputs, embeddings, logs), and for how long? | Short, stated retention; zero-retention option |
| Q3 | Human access | Can your staff read our prompts and outputs (for example abuse review)? Under what controls and logging? | Restricted, logged, purpose-limited |
| Q4 | Location | Where is data processed and stored? Which sub-processors? | Named regions and a sub-processor list with change notice |
| Q5 | Isolation | How are tenants separated (data, fine-tunes, vector stores, caches)? | Per-tenant keys and stores; tested |
| Q6 | Security assurance | Which independent reports cover this AI service (SOC 2 Type II, ISO/IEC 27001, ISO/IEC 42001)? What is in scope? | Current reports that name the service |
| Q7 | AI testing | Do you red-team the model and the product for prompt injection, data leakage and misuse? Can we see a summary? | Regular testing; shared summary |
| Q8 | Model changes | How do you notify customers of model or version changes and deprecations? Can we pin a version? | Advance notice; version pinning |
| Q9 | Incidents | What is your incident notification time? Have you had AI-related incidents? | Contractual time; honest history |
| Q10 | Agents and tools | If the product can act (send, write, buy, run code), what limits, approvals and logs exist? | Least privilege, approvals, audit log |
| Q11 | Documentation | Can you provide a model or system card, intended use and known limitations? | Current card with limitations |
| Q12 | IP and content | Who owns outputs? Do you offer indemnity? What is the licence of open-weight models used? | Clear terms |
| Q13 | Exit | How do we export our data and confirm deletion at the end? | Export format and deletion certificate |
| Q14 | Regulation | Which role do you take under the EU AI Act for this service (provider of a GPAI model or of an AI system)? What documentation do you give deployers? | Clear role and documentation |

## Appendix B. Vendor tiers

| Tier | When | Review depth |
|---|---|---|
| Tier 1 | Public or internal data only; no decisions about people; no actions | Short form: Q1, Q2, Q4, Q6 |
| Tier 2 | Confidential or personal data, or customer-facing output | Full questionnaire |
| Tier 3 | Sensitive personal data, decisions about people, autonomous actions, or a critical business process | Full questionnaire, evidence review, security testing, contract review, exit plan |
