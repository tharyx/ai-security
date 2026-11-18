# Tools Stack

The labs in this repo are **offline and pure Python**, so you learn the *mechanism* without installing anything heavy.
Real tools come next: each module lists them as **optional** steps. Learn a few tools well; don't try to learn every tool.

| Area | Tools | Where you meet them | Why it matters |
|---|---|---|---|
| Programming | Python, FastAPI, REST | Every lab | Most AI security tooling and glue is Python |
| LLM development | LangChain, LlamaIndex, Hugging Face | [03 RAG](../03-rag-security/), [05 agents](../05-agent-security/) | Know what the frameworks do by default, often insecurely |
| Local models | Ollama (`AISEC_LLM_BACKEND=ollama`) | Any lab that uses `aisec_lab.get_llm()` | Re-run attacks against a real model and measure success rates |
| RAG stores | FAISS, Chroma, pgvector | [03 · vector-db-security](../03-rag-security/vector-db-security/) | Metadata filtering, namespaces and deletion behave differently in each |
| MCP | Official MCP SDK, MCP Inspector | [04 MCP](../04-mcp-security/) | Inspect real tool definitions and traffic |
| Agent frameworks | LangGraph, AutoGen | [05 agents](../05-agent-security/) | Where tool policy and approvals plug in |
| LLM security testing | PyRIT, Garak, Promptfoo | [02 · security-testing](../02-llm-security/security-testing/) | Automated red teaming at scale |
| AI evaluation | DeepEval, Ragas | [02 · security-testing](../02-llm-security/security-testing/), [03](../03-rag-security/) | Measure groundedness, leakage and regressions |
| Testing guidance | OWASP AI Testing Guide | [02 · security-testing](../02-llm-security/security-testing/) | A structured test catalogue for AI systems |
| AppSec | OWASP ZAP, Burp Suite | [02 · data-leakage](../02-llm-security/data-leakage/) (output → XSS), [09 gateway](../09-enterprise-architecture/) | AI apps are still web apps |
| Cloud AI | AWS Bedrock (+ Guardrails), Azure AI Foundry (+ Prompt Shields), Vertex AI (+ Model Armor), IAM, GuardDuty | [09](../09-enterprise-architecture/) | Managed guardrails and identity controls |
| Infrastructure | Docker, Kubernetes, Terraform | [06](../06-ai-devsecops/) | Your existing strength; apply it to model serving |
| IaC/container scanning | Checkov, Trivy, hadolint, kube-linter, kubescape, OPA/conftest | [06](../06-ai-devsecops/) | Policy as code in CI |
| Model scanning | ModelScan, safetensors | [06 · docker](../06-ai-devsecops/docker/) | Malicious pickle models are real |
| Supply chain | pip-audit, Sigstore/cosign, SLSA, CycloneDX ML-BOM | [06 · cicd](../06-ai-devsecops/cicd/) | Provenance for code, data and models |
| Secrets | HashiCorp Vault, AWS Secrets Manager, Azure Key Vault | [06 · runtime-security](../06-ai-devsecops/runtime-security/) | Provider API keys are high-value targets |
| Monitoring | OpenTelemetry, Grafana, a SIEM | [06 · runtime-security](../06-ai-devsecops/runtime-security/), [10](../10-capstone-project/) | You cannot respond to what you don't log |
| CI/CD | GitHub Actions, Jenkins | [06 · cicd](../06-ai-devsecops/cicd/) | Where security gates run |

> Check a tool's current maintenance status, license and compatibility before adopting it in production. AI tooling changes quickly.

## A suggested order

1. **Weeks 5–8:** Ollama, then Promptfoo or Garak against the module 02 labs.
2. **Weeks 9–12:** Chroma or pgvector. Rebuild the access-control lab on a real store.
3. **Weeks 13–16:** MCP SDK + MCP Inspector. Port the hardened tools to a real MCP server.
4. **Weeks 17–20:** LangGraph. Put the module 05 policy engine in front of its tool node.
5. **Weeks 21–24:** Checkov, Trivy, ModelScan, cosign in a GitHub Actions workflow.
6. **Weeks 25–28:** one cloud's managed guardrail service (Bedrock Guardrails *or* Prompt Shields *or* Model Armor).
