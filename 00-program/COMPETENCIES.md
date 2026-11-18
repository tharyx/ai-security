# Competency Matrix

The 21 skills an AI Security Engineer/Architect should be able to **demonstrate**, not just describe.
Tick one only when you can show the evidence: the lab passes, you extended it yourself, and you can explain it in an interview without notes.

| # | Competency | Prove it here | Done |
|---|---|---|---|
| **1** | **AI fundamentals and architecture** | | |
| 1.1 | Explain transformer and LLM architecture (attention, context window, inference) | [01 · lesson 01b](../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) + [`tiny_llm.py`](../01-ai-security-fundamentals/lab/tiny_llm.py) | [ ] |
| 1.2 | Explain embeddings, tokens and inference, and their security effects | [`tiny_embeddings.py`](../01-ai-security-fundamentals/lab/tiny_embeddings.py) | [ ] |
| 1.3 | Explain training vs fine-tuning vs deployment, and the risks of each | [01 · lesson 01](../01-ai-security-fundamentals/01-ai-ml-llm-basics-for-security.md), [02 · model-threats](../02-llm-security/model-threats/) | [ ] |
| **2** | **LLM security** | | |
| 2.1 | Identify and exploit prompt injection (direct and indirect), then fix it | [02 · prompt-injection](../02-llm-security/prompt-injection/) | [ ] |
| 2.2 | Test jailbreaks and data leakage | [02 · jailbreak](../02-llm-security/jailbreak/), [02 · data-leakage](../02-llm-security/data-leakage/) | [ ] |
| 2.3 | Build automated LLM security tests with a CI gate | [02 · security-testing](../02-llm-security/security-testing/) (`redteam_cli.py`) | [ ] |
| **3** | **RAG security** | | |
| 3.1 | Build a secure RAG architecture | [03 · README](../03-rag-security/), [document-security](../03-rag-security/document-security/) | [ ] |
| 3.2 | Implement document-level authorization | [03 · access-control](../03-rag-security/access-control/) | [ ] |
| 3.3 | Test poisoning and cross-tenant leakage | [03 · access-control](../03-rag-security/access-control/), [vector-db-security](../03-rag-security/vector-db-security/) | [ ] |
| **4** | **MCP security** | | |
| 4.1 | Build an MCP server | [04 · mcp-server](../04-mcp-security/mcp-server/) (`servers.py`) | [ ] |
| 4.2 | Implement secure authentication and authorization | [04 · authentication](../04-mcp-security/authentication/) | [ ] |
| 4.3 | Test tool poisoning and command injection | [04 · tool-security](../04-mcp-security/tool-security/) | [ ] |
| **5** | **Agent security** | | |
| 5.1 | Build a tool-using AI agent | [05 · permissions](../05-agent-security/permissions/), [05 · mini-project](../05-agent-security/mini-project/) | [ ] |
| 5.2 | Implement agent identity and least privilege | [05 · agent-identity](../05-agent-security/agent-identity/) | [ ] |
| 5.3 | Implement human approval and sandboxing | [05 · permissions](../05-agent-security/permissions/), [sandboxing](../05-agent-security/sandboxing/) | [ ] |
| **6** | **AI governance and compliance** | | |
| 6.1 | Implement an AI inventory and risk register | [07 · lab](../07-ai-governance/lab/) | [ ] |
| 6.2 | Map controls to NIST AI RMF and ISO/IEC 42001 | [07 · lessons 03–04](../07-ai-governance/), [08 · control mapping](../08-ai-compliance/) | [ ] |
| 6.3 | Create audit evidence and compliance mappings | [08 · lab](../08-ai-compliance/lab/) (`evidence_checker.py`) | [ ] |
| **7** | **AI DevSecOps** | | |
| 7.1 | Integrate security tests into CI/CD | [06 · cicd](../06-ai-devsecops/cicd/) | [ ] |
| 7.2 | Secure models, containers and infrastructure | [06 · docker](../06-ai-devsecops/docker/), [kubernetes](../06-ai-devsecops/kubernetes/), [terraform](../06-ai-devsecops/terraform/) | [ ] |
| 7.3 | Implement monitoring and incident response | [06 · runtime-security](../06-ai-devsecops/runtime-security/), [10 · incident exercise](../10-capstone-project/03-red-team-and-incident-exercise.md) | [ ] |

**Progress:** count your ticks → `__ / 21`.

## How to prove a competency

1. Run the lab and its tests: `python -m pytest <folder>`.
2. **Extend it.** Add one attack and one test of your own, and commit them.
3. Write 5–10 lines in your journal: how it works, what fails without the control, and the residual risk.
4. Answer three of the lesson's interview questions out loud, without notes.

## Framework coverage at a glance

| Framework | Where |
|---|---|
| OWASP Top 10 for LLM Applications **2026** | [02 · README](../02-llm-security/) (full mapping) |
| OWASP Top 10 for Agentic Applications **2026** (ASI01–ASI10) | [05 · README](../05-agent-security/) (full mapping) |
| OWASP MCP Top 10 (2025, beta) | [04 · README](../04-mcp-security/) (full mapping) |
| OWASP GenAI Data Security (2026) | [02 · data-leakage](../02-llm-security/data-leakage/), [03](../03-rag-security/) |
| OWASP AI Testing Guide | [02 · security-testing](../02-llm-security/security-testing/) |
| MITRE ATLAS | [01 · threat modeling](../01-ai-security-fundamentals/03-ai-threat-modeling.md) |
| NIST AI RMF + GenAI Profile (AI 600-1) | [07](../07-ai-governance/) |
| ISO/IEC 42001, 23894, 27001 | [07](../07-ai-governance/), [08](../08-ai-compliance/) |
| EU AI Act (with the 2026 Digital Omnibus), GDPR, India DPDP | [08](../08-ai-compliance/) |
| CERT-In AI Security Auditing Guidelines | [08](../08-ai-compliance/) |
| NIST SP 800-207A (zero trust) | [09](../09-enterprise-architecture/) |
