# Assessment and Graduation Rubric

## Scoring model
Score each category from 0–4. A phase gate passes at 3 or higher in every critical category and at least 80% overall.

| Score | Meaning |
|---|---|
| 0 | Not attempted |
| 1 | Can describe terminology, cannot implement |
| 2 | Implements happy path with significant guidance |
| 3 | Independently implements and tests control |
| 4 | Explains trade-offs, failure modes, residual risk and operational evidence |

## Categories
1. Architecture and threat modeling.
2. Attack reproduction in a controlled lab.
3. Defensive implementation.
4. Automated regression testing.
5. Cloud/infrastructure integration.
6. Monitoring and incident response.
7. Governance and evidence.
8. Technical communication.

## Phase gates
- Month 1: coherent data-flow diagram, trust boundaries, assets, actors, abuse cases and prioritized threats.
- Month 2: prompt injection, data leakage and output handling test suite; controls enforced outside model instructions.
- Month 3: document-level authorization and cross-tenant tests pass; deletion and provenance behavior documented.
- Month 4: tool registry, identity, authorization, schema validation, timeouts and audit records demonstrated.
- Month 5: agent cannot exceed delegated permissions; high-impact actions require approval; kill switch tested.
- Month 6: CI/CD checks fail safely; model/dependency provenance recorded; container and secret controls tested.
- Month 7: AWS/Azure/GCP control mapping explains equivalent outcomes and provider-specific differences.
- Month 8: AI inventory, risk treatment, policy, applicability analysis and audit evidence pack complete.
- Month 9: end-to-end capstone passes security acceptance tests and architecture review.

## Final capstone scoring
| Area | Weight |
|---|---:|
| Threat model and architecture | 15% |
| LLM/RAG/MCP/agent security | 25% |
| Identity, data and infrastructure controls | 15% |
| Automated testing and CI/CD | 15% |
| Monitoring and incident response | 10% |
| Governance and compliance evidence | 10% |
| Documentation and architecture defense | 10% |

Graduation target: 80/100, with no unresolved critical finding. Any exception must be explicitly documented with owner, expiry, compensating controls and approval.

## Oral defense questions
- Why is prompt wording not an access-control mechanism?
- Where is authorization enforced in your RAG design?
- What happens if retrieved content contains hostile instructions?
- How do you prevent a tool from being invoked with a different user's authority?
- How are OAuth tokens scoped, stored, rotated and revoked?
- What limits an agent's blast radius?
- How do you prove model and dataset provenance?
- What evidence demonstrates that a control operated over time?
- Which regulatory obligations apply to this system, and why?
- What are the residual risks that cannot be eliminated technically?
