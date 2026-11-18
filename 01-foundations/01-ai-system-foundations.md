# Module 01 — AI System Foundations for Security Engineers

**Effort:** 12–16 hours. **Outcome:** Explain an AI system end-to-end and threat-model it before using exploit tooling.

## 1. Why AI security is a system problem
An enterprise AI solution is more than a model. It may include UI, identity provider, API gateway, orchestration, prompts, model endpoint, source data, parsers, embeddings, vector store, tools, MCP servers, agent memory, cloud infrastructure, logs and human operators. A model can generate a plausible response while the application leaks data or performs an unauthorized action. Therefore, security boundaries must surround the complete lifecycle.

## 2. Core concepts and security implications
- **AI / ML / deep learning / GenAI:** broad field, data-driven learning, neural-network methods and systems generating text/code/media. Training data, weights and serving runtime are assets.
- **Tokens/context window:** text is tokenized; context and output limits affect cost, truncation and abuse exposure. Enforce token and request budgets.
- **Transformer/attention:** models process relationships among tokens; they do not inherently understand enterprise authorization or data ownership.
- **Embeddings:** numeric representations used for similarity retrieval. Similarity is not permission and must never replace access control.
- **Inference:** using a deployed model. **Fine-tuning:** adapting model behavior. **Training:** optimizing parameters using data. Each stage has distinct integrity, privacy and supply-chain risks.
- **RAG:** retrieves external content into model context; it does not automatically enforce source permissions.
- **Tool calling:** model proposes a structured action; trusted code must validate, authorize and execute it.
- **Agent:** combines model, planning, memory, tools and repeated actions; autonomy expands blast radius.

## 3. Lifecycle threat map
| Stage | Assets | Threats |
|---|---|---|
| Data collection | Raw data, consent, labels | Poisoning, unlawful collection |
| Preparation | Parsers, filters, metadata | Parser exploit, label tampering |
| Training/fine-tuning | Dataset, weights, adapters | Backdoor, model theft |
| Packaging | Model artifact, dependencies | Supply-chain compromise |
| Deployment | Runtime, identity, endpoint | Misconfiguration, credential theft |
| Inference | Prompt, context, output | Injection, leakage, abuse |
| Retrieval | Documents, chunks, embeddings | Cross-tenant leakage, poisoning |
| Tool use | Schemas, tokens, APIs | Privilege escalation, SSRF |
| Operations | Logs, feedback, telemetry | Sensitive logging, drift, abuse |
| Retirement | Artifacts, indexes, backups | Incomplete deletion, lingering access |

## 4. Trust boundaries
Treat these as untrusted until validated: user prompts/files; retrieved documents/web pages/emails; model output and tool arguments; MCP tool descriptions/results; agent memory and inter-agent messages; third-party model/data packages; external telemetry. Every boundary needs a rule: authenticate, authorize, validate, sanitize, isolate, constrain or reject.

## 5. Threat modeling workflow
1. Define purpose, intended users, prohibited uses and business impact.
2. Draw components, data flows and trust boundaries.
3. Inventory data, models, prompts, credentials, tools, logs and infrastructure.
4. Identify actors: malicious users, compromised suppliers, hostile documents, rogue tools and insiders.
5. Write abuse cases in attacker language.
6. Rate likelihood, impact, exposure, reversibility and blast radius.
7. Select preventive, detective and recovery controls.
8. Create repeatable tests and evidence.
9. Record residual risk, owner, due date and expiry.

**Threat statement template:** `[Actor] can [action] through [entry point] because [weakness], causing [impact].`

Example: A tenant user can retrieve another tenant's HR chunk because the retrieval query lacks a server-derived tenant filter, exposing confidential data.

## 6. Lab — threat-model a toy assistant
Build a local FastAPI endpoint, mock model adapter, SQLite users/documents, retrieval function, one read-only tool and structured logs. Draw the user → API → identity → prompt builder → model → output validation path, plus retrieval and tool paths.

Exercises:
- Inventory every data store, identity, API, secret and log.
- Write 15 abuse cases: anonymous access, injection, cross-tenant retrieval, sensitive logs, unsafe tool arguments, token theft, expensive loops, malicious retrieved content, stale ACL, unauthorized model endpoint access, etc.
- For each high-risk case, define a preventive control, test and owner.

## 7. Knowledge check
1. Why is vector similarity not authorization?
2. Why is model output untrusted?
3. Distinguish inference from fine-tuning.
4. Name five trust boundaries in an agentic RAG system.
5. What evidence demonstrates a control operates over time?

## Acceptance criteria
- Diagram covers model, data, tools, identities and telemetry.
- At least 15 threats are documented and prioritized.
- Every high-risk threat has a control, test and owner.
- No secret is placed in prompts or source control.
- You can explain why prompt wording cannot enforce authorization.
