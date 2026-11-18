# Learning Resources: KodeKloud and Udemy

Courses that support each module of this roadmap. Use them to **learn the concept**, then **prove it in the repo lab**. A course does not replace the lab.

**How to use a course here:**
- Watch only the sections that match the current week. You do not have to finish every course.
- Watch at 1.25×, take notes in `journal/week-NN/`, then do the lab.
- Before buying a Udemy course, check its rating, the number of reviews and the "last updated" date. Many AI-security courses are new (2026) and quality varies.
- Catalogs change. This list was compiled in November 2026.

## Top 6 (if time is short)

| # | Course | Platform | Why |
|---|---|---|---|
| 1 | [AI Foundations for Technical Professionals](https://kodekloud.com/courses/ai-foundations-for-technical-professionals) | KodeKloud | Fast foundation; includes an "AI Security Essentials" section |
| 2 | [AI Engineer Core Track: LLM Engineering, RAG, QLoRA, Agents](https://www.udemy.com/course/llm-engineering-master-ai-and-large-language-models/) (Ed Donner) | Udemy | You must be able to *build* LLM and RAG apps to secure them |
| 3 | One OWASP LLM Top 10 course + one red-teaming course (see module 02) | Udemy | Core attack and defense knowledge |
| 4 | [Model Context Protocol Associate (MCPA) Certification](https://kodekloud.com/courses/model-context-protocol-associate-mcpa-certification) | KodeKloud | MCP trust boundaries, OAuth, attacks and audit, all in one course |
| 5 | [Certified Kubernetes Security Specialist (CKS)](https://kodekloud.com/courses/certified-kubernetes-security-specialist-cks) | KodeKloud | Respected certification; covers most of module 06 |
| 6 | [AI Risk Management Masterclass: NIST AI RMF & ISO 42001](https://www.udemy.com/course/ai-risk-management-masterclass-nist-rmf-iso-42001/) | Udemy | Lets you speak GRC language in architect interviews |

## By module

### 01 · AI Security Fundamentals (weeks 1–4)
- **KodeKloud:** [AI Foundations for Technical Professionals](https://kodekloud.com/courses/ai-foundations-for-technical-professionals): tokens, RAG, MCP, orchestration frameworks, AI security essentials.
- **Udemy:** [AI Engineer Core Track](https://www.udemy.com/course/llm-engineering-master-ai-and-large-language-models/), weeks 1–2: how LLMs work in code.
- **Repo:** [01-ai-security-fundamentals](../01-ai-security-fundamentals/)

### 02 · LLM Security (weeks 5–8)
- **Udemy, pick one OWASP course:**
  - [AI Security: Defend LLM Apps Against the OWASP LLM Top 10](https://www.udemy.com/course/ai-security-defend-llm-apps-against-the-owasp-llm-top-10/): labs across the full list.
  - [OWASP Top 10 for LLM Applications](https://www.udemy.com/course/owasp-top-10-for-llm-applications-2025/): category-by-category, with prompt-injection labs.
  - Alternative focused on injection: [Prompt Injection & LLM Defense](https://www.udemy.com/course/prompt-injection-llm-defense-2026/).
- **Udemy, then one red-teaming course:**
  - [Hands On AI (LLM) Red Teaming](https://www.udemy.com/course/hands-on-ai-llm-red-teaming/)
  - [OWASP GenAI Red Teaming Complete Guide](https://www.udemy.com/course/owasp-genai-red-teaming-complete-guide/)
- **Free extra practice:** PortSwigger Web Security Academy, "LLM attacks" labs.
- **Repo:** [02-llm-security](../02-llm-security/)

### 03 · RAG Security (weeks 9–12)
- **Udemy:** [AI Engineer Core Track](https://www.udemy.com/course/llm-engineering-master-ai-and-large-language-models/), the **Week 5 (RAG)** section only. If you prefer LangChain: [LangChain & LangGraph AI Engineer](https://www.udemy.com/course/langchain/).
- RAG-poisoning labs are also in the "Defend LLM Apps" course above.
- **Repo:** [03-rag-security](../03-rag-security/)

### 04 · MCP Security (weeks 13–16)
- **KodeKloud:** [MCP For Beginners](https://kodekloud.com/courses/mcp-for-beginners) (or the short [Crash Course](https://kodekloud.com/courses/crash-course-mcp-for-beginners)), then the [MCPA Certification course](https://kodekloud.com/courses/model-context-protocol-associate-mcpa-certification).
- **Udemy (optional):** [AI Agent Security 2026: Harden MCP & Block Prompt Injection](https://www.udemy.com/course/securing-ai-agents-tool-use-permissions-and-boundaries/). This course is very new, so check its reviews first.
- **Repo:** [04-mcp-security](../04-mcp-security/)

### 05 · Agent Security (weeks 17–20)
- **Udemy, build:** [AI Engineer Agentic Track: The Complete Agent & MCP Course](https://www.udemy.com/course/the-complete-agentic-ai-engineering-course/) (Ed Donner).
- **Udemy, secure:** [Agentic AI Security & Governance](https://www.udemy.com/course/agentic-ai-security-governance-build-safe-ai-agents/) or [AI Security & AI Guardrails: Agents, Red Teaming](https://www.udemy.com/course/ethical-secure-ai-guardrailsai-nvidia-nemo-guardrails/).
- **KodeKloud (free read):** [Running AI Agents Safely Inside Kubernetes](https://kodekloud.com/blog/running-ai-agents-safely-inside-kubernetes/).
- **Repo:** [05-agent-security](../05-agent-security/)

### 06 · AI DevSecOps (weeks 21–24)
- **KodeKloud:**
  - Terraform Basics (optionally HashiCorp Terraform Associate).
  - Docker for Absolute Beginners, if you need a refresher.
  - GitHub Actions.
  - [CKS](https://kodekloud.com/courses/certified-kubernetes-security-specialist-cks).
  - [Udemy Labs: DevSecOps](https://kodekloud.com/courses/udemy-labs-devsecops).
  - All of these are in the [KodeKloud course catalog](https://kodekloud.com/courses).
- **Repo:** [06-ai-devsecops](../06-ai-devsecops/)

### 09 · Enterprise Architecture (weeks 25–28)
- **KodeKloud:** [AWS Certified AI Practitioner / AWS AI learning path](https://kodekloud.com/learning-path/aws-ai) (focus on the security and governance section), and AI-102 Azure AI Engineer for Azure.
- **Udemy:** [AI Engineer Production Track: Deploy LLMs & Agents at Scale](https://www.udemy.com/course/generative-and-agentic-ai-in-production/) (AWS, GCP and Azure deployment).
- **Gap:** for Google Cloud AI security, use Google Cloud Skills Boost (free) and the Vertex AI security docs.
- **Repo:** [09-enterprise-architecture](../09-enterprise-architecture/)

### 07–08 · AI Governance & Compliance (weeks 29–32)
- **Udemy:**
  - [AI Risk Management Masterclass: NIST AI RMF & ISO 42001](https://www.udemy.com/course/ai-risk-management-masterclass-nist-rmf-iso-42001/)
  - For ISO 42001 depth: [ISO 42001 — AI Management System](https://www.udemy.com/course/iso-42001-artificial-intelligence-ai-management-system/)
  - If you want a certification: [IAPP AIGP Certification Prep](https://www.udemy.com/course/iapp-aigp-certification-eu-ai-act/)
- **Repo:** [07-ai-governance](../07-ai-governance/) · [08-ai-compliance](../08-ai-compliance/)

### 10 · Capstone (weeks 33–36)
- No new course. Reuse what you learned and focus on building, red-teaming and presenting. See [10-capstone-project](../10-capstone-project/).

## Certifications worth considering

| Certification | When | Prep |
|---|---|---|
| CKS (Kubernetes security) | After module 06 | KodeKloud CKS + mock exams |
| AWS AI Practitioner or Azure AI-102 | During module 09 | KodeKloud |
| MCPA (Model Context Protocol Associate) | After module 04 | KodeKloud MCPA course |
| IAPP AIGP (AI governance) | After modules 07–08, if you lean toward architecture/GRC | Udemy AIGP prep |
