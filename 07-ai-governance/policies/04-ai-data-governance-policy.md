# AI Data Governance Policy

| Field | Value |
|---|---|
| Policy ID | POL-AI-04 |
| Version | 1.0 |
| Owner | Chief Data Officer |
| Approved by | AI Governance Board |
| Effective | 2026-11-01 |
| Next review | 2027-11-01 |
| Status | Template: adapt to your organization before use |

## 1. Purpose

Data used to train, ground, evaluate or prompt AI systems is known, lawful, labelled, owned and deletable, including every copy the AI pipeline makes of it.

## 2. Scope

All data that enters an AI system: training and fine-tuning sets, evaluation sets, RAG corpora and their embeddings and indexes, prompts and outputs, logs and traces, agent memory, caches, and backups of all of these. It applies to internal data and to data from vendors, partners, users and the web.

## 3. Roles

| Role | Responsibility |
|---|---|
| Data owner | Decides who may use the data and for which AI purpose |
| Data steward | Writes and maintains the datasheet; keeps classification and lineage current |
| Technical owner | Builds pipelines that enforce labels, retention and deletion |
| DPO / privacy lead | Confirms lawful basis; reviews DPIAs; handles data-subject requests |
| Security | Runs ingestion scanners, DLP and access control on AI data stores |

## 4. Requirements

| ID | Requirement | How we check (evidence) |
|---|---|---|
| DGP-01 | Every dataset used for training, fine-tuning, evaluation or retrieval has a datasheet with owner, source, collection method, licence, classification, personal-data flag, retention and known gaps. | `doc_validator.py` datasheet checks (DS-01) |
| DGP-02 | Personal data is used for AI only with a recorded lawful basis (GDPR) or ground (DPDP: consent or a legitimate use) and a DPIA reference. | Datasheet fields; DPIA register (DS-02) |
| DGP-03 | Third-party and web-scraped data has a recorded licence or terms that allow the AI use. | Datasheet licence field; legal sign-off (DS-03) |
| DGP-04 | Classification labels follow the data: embeddings, index entries, fine-tune sets, logs, caches and backups carry at least the source's classification and access rules. | Datasheet derived-artifact labels (DS-04); index ACL test |
| DGP-05 | Ingestion pipelines scan for personal data, secrets and hidden instructions at every entry point, and block restricted data unless approved. | Pipeline scanner logs; blocked-ingestion report |
| DGP-06 | Every training run and every index build is linked to the exact dataset versions it used (data-to-model lineage). | Lineage records; model card `training_data` resolves (DOC-08) |
| DGP-07 | Retention is set for every store, enforced by automation, and never "forever". Backups expire. | Retention config export (DS-05); purge job logs |
| DGP-08 | Erasure requests reach every copy: source, chunks, embeddings, caches, logs (redacted), backups at expiry; fine-tuned weights are listed as pending with a plan. | Erasure receipt (Module 08 `privacy_rights.py`); quarterly deletion test |
| DGP-09 | Prompts and outputs sent to model providers contain only data classes approved for that provider. | Gateway DLP logs; vendor approval record |
| DGP-10 | Agent memory and conversation context have a time limit and are isolated per user or tenant. | Memory TTL config; cross-tenant test result |

## 5. Exceptions

Approved by the data owner and the DPO together, time-limited, recorded in the register. DGP-02 and DGP-08 cannot be waived where the law requires them.

## 6. Review cycle

Every year, and when data protection law changes (for example the phased start of India's DPDP Rules), or after a data incident involving an AI system.

## 7. Framework mapping

| Requirement | NIST AI RMF | ISO/IEC 42001 | Other |
|---|---|---|---|
| DGP-01, DGP-06 | MAP 2.2, MEASURE 2.9 | Annex A.7 (data for AI systems: acquisition, quality, provenance, preparation) | EU AI Act Art 10; CERT-In AI audit guideline 8.2 |
| DGP-02, DGP-08 | MEASURE 2.10 | Annex A.7, Clause 8.4 | GDPR Art 6, 17, 35; DPDP Act s.4, 7, 8, 12 |
| DGP-03 | GOVERN 6.1, MAP 4.1 | Annex A.10 | |
| DGP-04, DGP-05, DGP-09 | MEASURE 2.7, MAP 4.1 | Annex A.7 | OWASP GenAI Data Security Risks and Mitigations 2026 (DSGAI01, DSGAI07); OWASP LLM02:2026 |
| DGP-07 | GOVERN 1.7 | Annex A.7 | ISO/IEC 27001 A.8.10 (information deletion) |
| DGP-10 | MEASURE 2.10 | Annex A.6 | OWASP ASI06 Memory and Context Poisoning |
