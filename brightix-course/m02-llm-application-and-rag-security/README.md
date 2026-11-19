# Module 02: LLM Application & RAG Security (days 5–9)

How LLM applications and RAG pipelines are assembled, and where each stage (ingestion, chunking, embeddings, vector store, retrieval, generation) can be attacked or leak data.

> **How this module works.** Most topics are already taught in depth elsewhere in this repo, so the table links to those lessons and labs instead of repeating them. Rows marked **Gap filled here** had little or no hands-on material before; the **NEW** labs in this module fill them.

> **Safety.** Every attack lab targets the repo's own toy code and mock models. Only test systems you own or have written permission to test.

## Syllabus coverage

| Syllabus item | Where to study | Lab | Status |
|---|---|---|---|
| [BX 2] LLM Application Architecture & orchestration layers | [Architecture and trust boundaries](../../01-ai-security-fundamentals/02-ai-system-architecture-and-trust-boundaries.md); [Enterprise reference architecture](../../09-enterprise-architecture/01-enterprise-ai-reference-architecture.md); [Anatomy of an agent harness](../../caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/02-anatomy-of-an-agent-harness.md) | [minimal-agent-harness](../../caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/minimal-agent-harness) | Covered |
| [BX 2] RAG Architecture Deep Dive | [RAG security module](../../03-rag-security/README.md); [Retrieval and reranking](../../03-rag-security/retrieval-reranking/README.md) | [06-rag-system](../../caisp-course/ch2-understanding-and-attacking-llms/labs/06-rag-system); [secure HR assistant](../../03-rag-security/secure-hr-assistant/lab) | Covered |
| [BX 2] Embeddings & Vector Databases security | [Vector DB security](../../03-rag-security/vector-db-security/README.md) | [vector-db lab](../../03-rag-security/vector-db-security/lab) | Covered |
| [BX 2] Document Ingestion, Parsing & Chunking risks | [Document security](../../03-rag-security/document-security/README.md) | [document-security lab](../../03-rag-security/document-security/lab) | Covered |
| [BX 2] Retrieval Mechanisms & access control enforcement | [Access control (pre- vs post-filter)](../../03-rag-security/access-control/README.md) | [access-control lab](../../03-rag-security/access-control/lab) | Covered |
| [BX 2] RAG Security Risks (data poisoning, cross-tenant leakage) & Mitigations | [RAG security module](../../03-rag-security/README.md); [Vector DB security](../../03-rag-security/vector-db-security/README.md) | [02-rag-source-poisoning](../../caase-course/ch3-agent-memory-context-and-tool-use/labs/02-rag-source-poisoning); [access-control lab (tenant tests)](../../03-rag-security/access-control/lab) | Covered |

## Day-by-day plan

- Day 5: application architecture and orchestration layers; minimal agent harness lab.
- Day 6: RAG deep dive; build and query the RAG system lab.
- Day 7: embeddings and vector DB security; vector-db lab.
- Day 8: ingestion, parsing and chunking risks; document-security lab.
- Day 9: retrieval access control, poisoning and cross-tenant leakage; access-control and source-poisoning labs.

## Interview / exam questions

<details><summary><b>Pre-filter or post-filter for document permissions in RAG, and why?</b></summary>

Pre-filter: apply the user's ACL in the vector query so forbidden chunks are never retrieved. Post-filtering after the LLM has seen them is too late, and filtering after top-k can silently return fewer or wrong results.

</details>

<details><summary><b>How does one poisoned document affect many users?</b></summary>

Once indexed, it is retrieved for every matching query across users; indirect instructions inside it act with each user's session and tools.

</details>

<details><summary><b>Can embeddings leak the original text?</b></summary>

Yes. Embedding inversion can reconstruct much of the text, so treat vectors as sensitive as the source documents (encryption, tenancy, access control).

</details>

---

Previous: [Module 01](../m01-llm-security-fundamentals/README.md) · [Course home](../README.md) · Next: [Module 03](../m03-llm-vulnerabilities-owasp/README.md)
