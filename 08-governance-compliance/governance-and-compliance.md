# AI Governance, Risk, Privacy and Compliance

## Governance operating model
AI governance establishes accountability for AI systems from intake through retirement. It is not a substitute for technical controls.

### Minimum governance artifacts
- AI acceptable-use policy.
- AI system inventory and owner register.
- Intended-use and prohibited-use statement.
- AI impact/risk assessment.
- Data governance and privacy assessment.
- Model/provider due diligence.
- Security threat model.
- Human oversight and escalation design.
- Evaluation and monitoring plan.
- Incident response and change management.
- Decommissioning and retention plan.
- Audit evidence index.

## AI system inventory fields
| Field | Description |
|---|---|
| System ID | Unique stable identifier |
| Business owner | Accountable business role |
| Technical owner | Engineering/service owner |
| Purpose | Intended business use |
| Users/subjects | Who uses or is affected |
| Model/provider | Model, version and provider |
| Data | Input, retrieval, training and output classes |
| Tools | External systems/actions accessible |
| Deployment | Cloud, region, environment |
| Risk tier | Organization-defined classification |
| Legal scope | Jurisdictions and applicable obligations |
| Human oversight | Approval, review and appeal |
| Status | Proposed, pilot, production, retired |

## Risk management workflow
1. Context: purpose, users, affected parties, operating environment.
2. Identify: harms, security threats, privacy risks, misuse and failure modes.
3. Analyze: likelihood, severity, exposure, detectability and reversibility.
4. Evaluate: compare with risk appetite and legal requirements.
5. Treat: avoid, mitigate, transfer or accept with accountable approval.
6. Monitor: incidents, changes, drift, abuse and control effectiveness.
7. Communicate: owners, affected parties, regulators and auditors as applicable.

## Frameworks: understand their role
- **NIST AI RMF 1.0:** voluntary risk-management framework organized around Govern, Map, Measure and Manage.
- **NIST AI 600-1 GenAI Profile:** companion resource focused on generative AI risks.
- **ISO/IEC 42001:2023:** requirements for an AI management system (AIMS); certification is an organizational management-system activity, not a product security badge.
- **ISO/IEC 23894:2023:** guidance for AI-related risk management.
- **ISO/IEC 27001:** information security management system; use relevant controls as part of the wider security program.
- **OWASP GenAI guidance:** technical security guidance, not legislation.
- **EU AI Act:** legal obligations depend on role, system classification, use case and jurisdiction.
- **India DPDP Act and Rules:** assess applicability, commencement/transition provisions, data fiduciary/processor roles and current notifications with qualified counsel.

## Compliance mapping method
For every requirement:
1. quote/identify the authoritative requirement;
2. determine applicability and rationale;
3. map to a control objective;
4. define implementation and control owner;
5. define evidence and testing frequency;
6. record exceptions and remediation;
7. re-check when law, standards or system scope changes.

Do not label a system "compliant" because a checklist is complete. Compliance is scoped, evidence-based and subject to legal interpretation.

## Privacy engineering
- minimize collection and prompt/context content;
- define purpose and lawful basis;
- map data subject and data flows;
- apply retention/deletion to source, cache, logs, embeddings and backups;
- restrict access by role and purpose;
- document provider/subprocessor processing;
- evaluate cross-border transfers and residency;
- define rights request and incident workflows;
- use synthetic or de-identified data for labs.

## Vendor/model provider assessment
Assess training/use of submitted data, retention, human access, regions, subprocessors, security reports, encryption, tenant isolation, incident notification, model change notice, deletion, audit rights, IP/license, service continuity and exit/export.
