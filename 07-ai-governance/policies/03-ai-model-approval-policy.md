# AI Model Approval Policy

| Field | Value |
|---|---|
| Policy ID | POL-AI-03 |
| Version | 1.0 |
| Owner | Head of AI Engineering |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-11-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Only approved models, in approved versions, run in production. An approval covers one exact artifact, for one system, for a limited time.

## 2. Scope

Every model used by a registered AI system: vendor API models, open-weight models, fine-tunes, embedding models, classifiers and guard models. A new version, a new fine-tune or a change of provider needs a new approval.

## 3. Roles

| Role | Responsibility |
|---|---|
| Requester (technical owner) | Prepares the request: model card, evaluations, risk link, rollback plan |
| Security | Reviews security evaluation results; approves medium tier and above |
| Risk owner | Accepts the residual risk for high and critical systems |
| AI Governance Board | Approves critical-tier models |
| Platform team | Runs the model registry and the deployment check |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| APR-01 | Each request pins one artifact: a version label and its SHA-256 (or the provider's immutable model ID). "latest" is never approved. | Model registry entry; lab finding MA-01 |
| APR-02 | The model card passes the documentation validator with zero findings. | `doc_validator.py` report attached to the request (MA-02) |
| APR-03 | Required evaluations pass their thresholds: quality (all tiers); security, including the prompt-injection regression suite (medium and above); fairness (high and above). | CI evaluation report with dataset IDs (MA-03) |
| APR-04 | High and critical systems link an owned risk entry that the risk owner has accepted. | Risk register entry ID (MA-04) |
| APR-05 | Third-party models have a vendor assessment not older than 12 months. | Vendor assessment record (MA-05) |
| APR-06 | Approvals by tier: low: technical owner; medium: plus security; high: plus risk owner; critical: plus AI Governance Board. | Approval records in the registry (MA-06) |
| APR-07 | Separation of duties: the requester cannot approve in an oversight role. | Registry check (MA-07) |
| APR-08 | High and critical systems have a tested rollback to the previous approved version. | Rollback test record (MA-08) |
| APR-09 | Approvals expire: 12 months for low and medium, 6 months for high, 3 months for critical. | Registry `valid_until` field |
| APR-10 | The deployment pipeline runs a model only if its hash matches an unexpired approval for that system. A mismatch blocks the deploy. | Pipeline logs of `can_deploy`; blocked-deploy alerts |
| APR-11 | Vendors must give notice of model changes; provider-side updates are detected by pinning and by monitoring output drift. | Contract clause; drift monitor alerts |
| APR-12 | Retired models are removed from the registry, their endpoints and keys are disabled, and their data follows the retention rules. | Decommissioning checklist |

## 5. Exceptions

Emergency patch (for example a security fix to a guard model): the security lead may approve for up to 14 days; the full approval must follow. APR-01, APR-07 and APR-10 cannot be waived.

## 6. Review cycle

Every year, and when the release pipeline or the model-hosting platform changes.

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| APR-01, APR-10 | MANAGE 2.4, MAP 4.1 | Annex A.6 (AI system life cycle) | OWASP LLM04:2026 Supply Chain; OWASP ASI04 Agentic Supply Chain |
| APR-02 | MAP 2.2, MEASURE 2.9 | Annex A.6, A.8 | EU AI Act Art 11 and 13 |
| APR-03 | MEASURE 2.7, MEASURE 2.11 | Annex A.6 (verification and validation) | EU AI Act Art 15 |
| APR-04, APR-06, APR-07 | GOVERN 2.1, GOVERN 2.3, MANAGE 1.3 | Clause 5.3, 8.3 | CERT-In AI Security Auditing Guidelines 8.3 (model risk management) |
| APR-05, APR-11 | GOVERN 6.1, MANAGE 3.1 | Annex A.10 | |
| APR-08, APR-09 | MANAGE 2.3, MANAGE 2.4 | Annex A.6 | |
| APR-12 | GOVERN 1.7 | Annex A.6 | |
