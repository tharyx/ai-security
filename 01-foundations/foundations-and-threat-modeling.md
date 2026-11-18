# AI Foundations and Security Threat Modeling

## 1. The system, not just the model
An enterprise AI system may include:
- user interface and API gateway;
- identity provider and authorization service;
- prompt templates and orchestration;
- model provider or self-hosted inference;
- source data, embeddings and vector index;
- tools, plugins and MCP servers;
- agent planner, memory and workflow engine;
- cloud infrastructure, secrets and telemetry;
- humans approving, reviewing and operating the system.

Security review must cover the complete system and lifecycle: acquire data → prepare data → train/fine-tune or select model → deploy → infer → retrieve → call tools → monitor → update/decommission.

## 2. Concepts to understand
- **Tokenization:** converts input into model tokens; token count affects context and cost.
- **Embedding:** numeric representation used for semantic similarity; not an authorization token.
- **Transformer/attention:** model architecture that processes token relationships.
- **Inference:** generation using a deployed model.
- **Fine-tuning:** modifies model behavior using additional examples.
- **RAG:** retrieves external content and supplies it as context; it does not inherently enforce access control.
- **Tool calling:** model proposes a structured action; trusted application code must validate and authorize it.
- **Agent:** orchestrates model reasoning, state, tools and actions over multiple steps.

## 3. Threat-model workflow
1. Define system purpose, intended users and prohibited uses.
2. Draw components, data flows, trust boundaries and external dependencies.
3. Inventory assets: data, prompts, models, credentials, tools, logs, memory and infrastructure.
4. Identify actors: legitimate users, malicious users, compromised vendors, malicious documents, rogue tools and insiders.
5. Write abuse cases in attacker language.
6. Rate likelihood, impact, exploitability and blast radius.
7. Select preventive, detective and recovery controls.
8. Define test cases and evidence.
9. Record residual risk, owner and expiry.

## 4. Trust boundaries
Treat these as untrusted until validated:
- user prompts and uploaded files;
- retrieved web pages and documents;
- model output and tool arguments;
- tool descriptions and MCP server content;
- agent memory and messages from other agents;
- model/dataset packages from external registries;
- telemetry that may contain sensitive values.

## 5. STRIDE adapted to AI
| Threat class | AI examples |
|---|---|
| Spoofing | Fake MCP server, forged agent identity |
| Tampering | Dataset poisoning, prompt/template modification |
| Repudiation | Missing tool-call audit trail |
| Information disclosure | RAG cross-tenant leak, prompt/data exposure |
| Denial of service | Expensive prompts, recursive agent loops |
| Elevation of privilege | Agent invokes privileged tool or abuses delegated token |

Add AI-specific lenses: prompt injection, model extraction, membership inference, evasion, poisoning, unsafe autonomy, retrieval manipulation and evaluation gaming.

## 6. Threat statement template
`[Actor] can [action] through [entry point] to affect [asset] because [weakness], resulting in [impact].`

Example: A tenant user can retrieve another tenant's HR chunk through a shared vector index because the retrieval query lacks a server-enforced tenant filter, resulting in confidential data disclosure.

## 7. Lab
Create a local architecture with:
- FastAPI endpoint;
- mock LLM response;
- SQLite users/documents;
- local vector store or a simple in-memory retrieval substitute;
- one read-only tool;
- structured logs.

Draw all data flows. Identify at least 15 threats, rank them, and map each to a test and control.

## 8. Acceptance criteria
- No component is omitted from the diagram.
- Every trust boundary has an explicit validation/authorization rule.
- Each high-risk threat has an owner, mitigation and test.
- Model behavior is not relied on as the sole security control.
