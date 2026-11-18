# 36-Week Master Plan

## Month 1 — AI foundations and security architecture
| Week | Focus | Build / prove |
|---|---|---|
| 1 | AI/ML/GenAI landscape, lifecycle, actors and assets | Draw lifecycle and asset inventory |
| 2 | Transformers, tokens, embeddings, context windows, inference | Small local inference/embedding experiment |
| 3 | AI application architecture, APIs, data flows, trust boundaries | Data-flow diagram and trust-boundary map |
| 4 | Threat modeling, abuse cases, risk scoring, security requirements | Threat model review and Phase 1 gate |

## Month 2 — LLM application security
| Week | Focus | Build / prove |
|---|---|---|
| 5 | Prompt injection, direct/indirect, instruction/data separation | Controlled prompt-injection test harness |
| 6 | Sensitive data disclosure, system prompt exposure, privacy | Synthetic secret-leak tests and redaction controls |
| 7 | Output handling, structured output, tool calling, code execution | Schema validation and safe output handling |
| 8 | Model abuse, denial of service, supply chain, evaluation | Rate limits, quotas, model/dependency inventory; Phase 2 gate |

## Month 3 — RAG security
| Week | Focus | Build / prove |
|---|---|---|
| 9 | Ingestion, parsing, chunking, metadata and provenance | Ingestion pipeline with file validation |
| 10 | Embeddings, vector stores, index lifecycle and deletion | Vector-store security baseline |
| 11 | Authorization-aware retrieval, tenant isolation, ACL propagation | Cross-tenant isolation tests |
| 12 | Poisoning, indirect injection, retrieval evaluation and DLP | RAG red-team suite; Phase 3 gate |

## Month 4 — MCP security
| Week | Focus | Build / prove |
|---|---|---|
| 13 | MCP architecture, hosts, clients, servers, tools/resources/prompts | Draw MCP data/control flow |
| 14 | Identity, OAuth, token lifecycle, scopes and authorization | Authenticated MCP service design |
| 15 | Tool poisoning, command injection, SSRF, path traversal, supply chain | Tool allowlist and schema enforcement |
| 16 | Logging, server registry, transport hardening and governance | MCP security gateway prototype; Phase 4 gate |

## Month 5 — Agentic AI security
| Week | Focus | Build / prove |
|---|---|---|
| 17 | Agent lifecycle, planner/executor, memory, orchestration | Threat-model a single agent |
| 18 | Agent identity, delegated authority, least privilege | Per-agent identity and scoped tool policy |
| 19 | Memory poisoning, multi-agent trust, context isolation | Memory isolation and provenance tests |
| 20 | Human approval, sandboxing, rollback, kill switch | Controlled cloud-read-only agent; Phase 5 gate |

## Month 6 — AI DevSecOps and model supply chain
| Week | Focus | Build / prove |
|---|---|---|
| 21 | Secure AI SDLC, requirements, design review and testing | AI security gates in SDLC |
| 22 | Model/dataset provenance, artifacts, dependencies and licenses | Model bill of materials/inventory |
| 23 | Containers, Kubernetes, secrets, network and workload identity | Hardened deployment baseline |
| 24 | CI/CD, adversarial testing, telemetry and incident response | Reproducible pipeline; Phase 6 gate |

## Month 7 — Multi-cloud AI security architecture
| Week | Focus | Build / prove |
|---|---|---|
| 25 | AWS AI services, IAM, network, logging, key management | AWS reference deployment design |
| 26 | Azure AI services, Entra ID, network, policy and monitoring | Azure reference deployment design |
| 27 | Google Cloud AI services, IAM, VPC, CMEK and audit logs | GCP reference deployment design |
| 28 | Multi-cloud control equivalence, portability and shared responsibility | Cloud control matrix; Phase 7 gate |

## Month 8 — AI governance, risk, privacy and compliance
| Week | Focus | Build / prove |
|---|---|---|
| 29 | AI inventory, system context, intended use and classification | AI system register |
| 30 | Risk assessment, NIST AI RMF, ISO/IEC 42001 and 23894 | AI risk register and treatment plan |
| 31 | Privacy, data protection, retention, DPIA and vendor risk | Privacy impact and vendor assessment |
| 32 | EU AI Act, India DPDP, audit evidence and policy lifecycle | Compliance applicability matrix; Phase 8 gate |

## Month 9 — Enterprise capstone and architecture defense
| Week | Focus | Build / prove |
|---|---|---|
| 33 | Architecture, threat model, security requirements and design review | Approved architecture pack |
| 34 | Build secure LLM + RAG + MCP + agent vertical slice | Working application and tests |
| 35 | Red team, cloud deployment, CI/CD, monitoring and incident exercise | Test report and operational runbook |
| 36 | Governance evidence, risk acceptance, architecture presentation | Final defense and Phase 9 gate |

## Weekly timebox
- 3h: study and notes.
- 4h: implement.
- 2h: attack and test.
- 1h: write a short design decision record.
- 2h: review, quiz, remediation and portfolio cleanup.

## Weekly definition of done
- [ ] Concepts explained in your own words.
- [ ] Diagram updated.
- [ ] Code committed with tests.
- [ ] Attack scenario reproduced safely.
- [ ] Mitigation implemented and regression-tested.
- [ ] Risk register updated.
- [ ] Evidence saved without secrets or personal data.
- [ ] Short retrospective: what failed, what changed, residual risk.
