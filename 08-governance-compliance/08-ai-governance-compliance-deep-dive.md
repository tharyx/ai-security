# Module 08 — AI Governance, Risk, Privacy and Compliance

**Effort:** 22–28 hours. **Outcome:** Establish an AI management and assurance process with traceable controls and evidence.

## 1. Governance questions
Why is the AI system used? Who owns it? Who may be affected? What data/models/tools are involved? What risks are acceptable? Who approves release and changes? How are incidents handled? How is it retired?

## 2. AI inventory fields
System ID; business purpose; business/technical owner; users and affected groups; model/provider/version; data sources/classification; tools and connected systems; region/environment; risk tier; intended/prohibited use; human oversight; legal jurisdictions; evaluation/monitoring status; approval and lifecycle state.

## 3. Risk management workflow
1. Define context and intended use.
2. Identify security, privacy, safety, operational and misuse harms.
3. Analyze likelihood, severity, exposure, reversibility and affected parties.
4. Evaluate against risk appetite and legal requirements.
5. Treat by avoiding, mitigating, transferring or accepting with approval.
6. Monitor control effectiveness and changes.
7. Communicate material risks and incidents.

Reassess when model, data, tools, user population, purpose, region or architecture changes.

## 4. Frameworks — understand their role
- **NIST AI RMF 1.0:** voluntary risk-management framework organized around Govern, Map, Measure and Manage.
- **NIST AI 600-1 GenAI Profile:** companion resource focused on generative AI risks.
- **ISO/IEC 42001:2023:** requirements for an AI management system (AIMS); not a product security certification.
- **ISO/IEC 23894:2023:** AI risk-management guidance.
- **ISO/IEC 27001:** information security management system foundation; integrate AI controls with wider security.
- **OWASP GenAI guidance:** technical security guidance, not legislation.
- **EU AI Act:** legal obligations depend on role, classification, use and jurisdiction.
- **India DPDP Act and Rules:** assess processing, roles, applicable duties and current commencement/transition notifications.

## 5. Compliance mapping method
For each requirement: identify authoritative clause/article; record applicability and rationale; define control objective; describe implementation; assign owner; define evidence and test frequency; record exceptions and expiry; reassess after legal/system changes. A checklist does not itself prove compliance. Seek qualified legal advice for formal interpretation.

## 6. Privacy engineering
Minimize collection and prompt context; define purpose and lawful basis; map data flows and subjects; apply retention/deletion to source, caches, logs, embeddings and backups; restrict access; document processors/subprocessors; assess transfers/residency; define rights and incident workflows; use synthetic/de-identified lab data.

## 7. Vendor/model provider assessment
Assess training/use of submitted data, retention, human access, regions, subprocessors, security reports, encryption, tenant isolation, incident notification, deletion, audit rights, model change notice, IP/license, continuity and exit/export.

## 8. Practical labs
- Create an AI inventory for the capstone.
- Build 15+ risks across security, privacy, safety, reliability, misuse and third-party dependencies.
- Assess a model provider using the checklist above.
- For each control, collect policy, configuration, test result, owner and review date.
- Build an applicability matrix for an Indian organization serving EU customers; identify questions requiring legal counsel.

## Exercises
1. Why does a provider certification not automatically make your application compliant?
2. Distinguish a management-system standard from a technical vulnerability taxonomy.
3. What evidence proves deletion, access control and human oversight?
4. What system changes trigger risk reassessment?

## Acceptance criteria
Inventory complete; risk register has owners/treatments; laws and standards correctly distinguished; applicability documented from authoritative sources; evidence is repeatable; review triggers defined.
