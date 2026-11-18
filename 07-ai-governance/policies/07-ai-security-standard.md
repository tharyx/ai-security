# AI Security Standard (technical controls)

| Field | Value |
|---|---|
| Policy ID | STD-AI-07 |
| Version | 1.0 |
| Owner | CISO |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-05-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Turn the AI policies into measurable engineering controls. Each control is either enforced in code (hard), done by people with records (process), or a probabilistic filter (soft). A soft control is never the only control for a high risk.

## 2. Scope

Every AI system built or configured by the organization: LLM applications, RAG systems, agents, MCP servers and clients, model serving, and the CI/CD and cloud resources around them. The control set grows with the system's risk tier (Section 4 column "Tier").

## 3. Roles

| Role | Responsibility |
|---|---|
| Technical owner | Implements the controls; keeps evidence |
| Security architecture | Owns this standard; reviews designs of high and critical systems |
| Platform team | Provides shared controls (AI gateway, secrets, logging, model registry) |
| Red team / AppSec | Tests the controls before release and after major changes |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| SEC-01 | Tier: all. All model access goes through the AI gateway with SSO identity, per-user rate limits and a spend budget. | Gateway config export; no direct provider keys in apps (secret scan) |
| SEC-02 | Tier: all. Secrets (API keys, tokens) live in a secrets manager, never in prompts, code, notebooks or images. | Secret scanning in CI; rotation log |
| SEC-03 | Tier: medium and above. Untrusted content (user input, web pages, emails, documents, tool results) is kept separate from instructions and never gains authority to call tools. | Threat model; prompt-injection regression suite in CI |
| SEC-04 | Tier: medium and above. Every tool call goes through a policy check outside the model (allowlist, argument validation, per-user authorization). The model proposes, the system decides. | Tool-broker policy file; denied-call logs |
| SEC-05 | Tier: high and above. Actions with side effects (send, pay, delete, deploy, change access) need human approval or a hard rule that limits them. | Approval log sample (CTL-HO) |
| SEC-06 | Tier: medium and above. Retrieval enforces the user's own permissions before ranking (no cross-tenant or cross-user results). | Access-control test results (Module 03) |
| SEC-07 | Tier: all. Model output is treated as untrusted: encoded for its sink (HTML, SQL, shell), and links or images to unknown domains are blocked. | Output-handling tests; CSP config |
| SEC-08 | Tier: medium and above. Agents run with their own identity, least privilege and short-lived credentials; code execution happens only in a sandbox without network by default. | IAM policy export; sandbox config |
| SEC-09 | Tier: all. MCP servers are allowlisted, pinned, authenticated (no token pass-through) and their tool descriptions are reviewed and hash-pinned. | MCP allowlist; pin file; review records |
| SEC-10 | Tier: all. Models, datasets and containers come from approved sources, are pinned by hash, scanned, and use safe formats (for example safetensors, not pickle). | Model registry; CI scan reports |
| SEC-11 | Tier: medium and above. Logs record prompts, tool calls, decisions, model version and user identity, with personal data redacted, kept at least 180 days and protected from change. | Logging config export; retention test |
| SEC-12 | Tier: medium and above. A security evaluation (prompt-injection, data-leakage and misuse tests) runs in CI on every model, prompt or tool change and blocks release on failure. | CI test report (CTL-EVAL) |
| SEC-13 | Tier: high and above. A red-team exercise runs before first release and after major changes. | Red-team report; fixes verified |
| SEC-14 | Tier: all. Data stores of AI systems (vector databases, caches, memory) are encrypted, access-controlled and in the asset inventory. | Cloud config export; inventory |
| SEC-15 | Tier: high and above. Runtime monitoring alerts on abuse patterns: injection markers, unusual tool sequences, spend spikes, data-volume spikes. | Alert rules; SOC runbooks |

## 5. Exceptions

Through the exception process in the register (key such as `GOV-05:CTL-RT`), approved by the CISO, with compensating controls and an expiry date of at most 6 months. SEC-02, SEC-04 and SEC-09 cannot be waived for systems with side-effecting tools.

## 6. Review cycle

Every 6 months, because attack techniques and the OWASP lists change; also after any SEV1 AI incident or a new OWASP Top 10 release.

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | OWASP (2026 lists) |
|---|---|---|---|
| SEC-01, SEC-02 | MEASURE 2.7 | Annex A.4 (resources), A.6 | LLM06 Unbounded Consumption; MCP01 Token Mismanagement and Secret Exposure |
| SEC-03 | MEASURE 2.7 | Annex A.6 | LLM01 Prompt Injection; ASI01 Agent Goal Hijack; MCP06 Prompt Injection via Contextual Payloads |
| SEC-04, SEC-05 | MAP 3.5, MANAGE 2.4 | Annex A.9 | LLM03 Excessive Agency; ASI02 Tool Misuse; ASI09 Human-Agent Trust Exploitation |
| SEC-06 | MEASURE 2.10 | Annex A.7 | LLM09 Vector and Embedding Weaknesses; LLM02 Sensitive Information Disclosure |
| SEC-07 | MEASURE 2.7 | Annex A.6 | LLM10 Improper Output Handling |
| SEC-08 | GOVERN 3.2, MEASURE 2.7 | Annex A.6 | ASI03 Identity and Privilege Abuse; ASI05 Unexpected Code Execution |
| SEC-09 | GOVERN 6.1 | Annex A.10 | MCP02 Privilege Escalation via Scope Creep; MCP03 Tool Poisoning; MCP07 Insufficient Authentication and Authorization; MCP09 Shadow MCP Servers |
| SEC-10 | GOVERN 6.1, MAP 4.1 | Annex A.6, A.10 | LLM04 Supply Chain; LLM05 Data and Model Poisoning; ASI04 Agentic Supply Chain |
| SEC-11, SEC-15 | MEASURE 3.1, MANAGE 4.1 | Annex A.6 (event logs) | MCP08 Lack of Audit and Telemetry; ASI10 Rogue Agents |
| SEC-12, SEC-13 | MEASURE 2.7, MEASURE 1.1 | Annex A.6 (verification and validation) | All; EU AI Act Art 15 |
| SEC-14 | MEASURE 2.7 | Annex A.7 | LLM08 Hidden Context Exposure; ISO/IEC 27001 A.8.24 (cryptography) |

Numbering note: the OWASP Top 10 for LLM Applications 2026 renumbered several entries (for example Excessive Agency moved from LLM06:2025 to LLM03:2026). Check the current lists at genai.owasp.org and owasp.org/www-project-mcp-top-10.
