# Portfolio and Interview Guide

## Portfolio projects to showcase
1. LLM red-team and regression-testing harness.
2. Secure multi-tenant RAG assistant.
3. MCP security gateway with tool authorization.
4. Agent with identity, approval and sandbox controls.
5. Multi-cloud AI security reference architecture.
6. AI governance and compliance evidence pack.

## Every project README should contain
- business problem and intended use;
- architecture diagram;
- threat model and trust boundaries;
- attack scenarios reproduced in a safe lab;
- controls and why they work;
- test results and residual risks;
- deployment instructions;
- cost and operational assumptions;
- limitations and future improvements.

## Interview questions to prepare
### Architecture
- Design a secure enterprise RAG system for multiple departments.
- How do you secure an LLM gateway across multiple model providers?
- How would you isolate agents and their memories?
- How do you manage MCP server trust and tool authorization?

### Threats
- Explain direct versus indirect prompt injection.
- Why are system prompts not secrets or authorization controls?
- How can a vector database leak data across tenants?
- What is tool poisoning and how do you detect it?
- How can an agent be manipulated through memory?

### Engineering
- How do you validate model output before executing a tool?
- How do you implement short-lived cloud credentials for agents?
- What security checks belong in an AI CI/CD pipeline?
- How do you test that access revocation works for RAG?

### Governance
- Explain NIST AI RMF Govern, Map, Measure and Manage.
- How does ISO/IEC 42001 differ from a technical security checklist?
- How do you decide whether the EU AI Act applies?
- What evidence would an auditor expect for an AI system?

## Strong answer structure
1. Clarify the system and threat model.
2. Identify assets and trust boundaries.
3. State the security invariant.
4. Describe preventive controls.
5. Describe detective and recovery controls.
6. Explain trade-offs and residual risk.
7. Describe how you test and prove effectiveness.
