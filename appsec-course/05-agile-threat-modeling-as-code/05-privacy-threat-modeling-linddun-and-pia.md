# Lesson 05: Privacy Threat Modeling with LINDDUN and Privacy Impact Assessments

**Syllabus items covered:** [CTMP 3] "Privacy Impact Assessments and Security Requirements", "Identifying Privacy Related Threats", "Threat Modeling Privacy for your system".

**Time:** 1.5 hours plus lab. **Safety:** fictional systems only. This is not legal advice.

> **DBA analogy.** **Linking** is a join: two tables that share a column (a device id, a phone number) can be joined, even if each table looks harmless alone. **Pseudonymisation** is a surrogate key that is different per consumer, so the join is impossible without a mapping table you keep locked away.

## 1. Privacy is not the same as security

Security asks "can an **attacker** read or change the data?". Privacy also asks "is the **system itself**, used as designed, treating people's data fairly?". A perfectly secure system can still violate privacy: it collects more than it needs, keeps it forever, shares one id with ten ad networks, or gives users no way to see or delete their data. That is why privacy needs its own threat categories.

## 2. Privacy impact assessments and security requirements

| Term | What it is |
|---|---|
| **PIA** (privacy impact assessment) | A structured review of how a project collects, uses, shares and keeps personal data, and the risks to people |
| **DPIA** (data protection impact assessment) | The GDPR form of a PIA, **mandatory** under GDPR Art. 35 when processing is "likely to result in a high risk", for example large-scale sensitive data, systematic monitoring of public areas, or automated decisions with legal effect |
| **India DPDP Act 2023** | India's Digital Personal Data Protection Act; the **DPDP Rules were notified in November 2025** and apply in phases (verify the dates). Significant Data Fiduciaries must carry out periodic DPIAs and audits (verify the details) |

**When is a DPIA needed?** The EDPB/WP29 guidelines list nine criteria (evaluation or scoring, automated decisions with significant effect, systematic monitoring, sensitive data, large scale, matching datasets, vulnerable data subjects, innovative technology, processing that blocks a right or service). Rule of thumb: **two or more criteria → do a DPIA.** Your regulator may publish its own list.

**A DPIA contains:** a description of the processing and its purpose; necessity and proportionality (is each data item needed?); the risks to people; the measures to address them; sign-off by the DPO or privacy lead.

**From PIA to security requirements.** Each risk becomes a requirement in the backlog, just like threat model findings:

| PIA finding | Requirement |
|---|---|
| Date of birth collected but only an age band is needed | Collect `age_band`; drop `date_of_birth` (minimisation) |
| No retention set | Delete workout data after 12 months; scheduled purge job with a test |
| Emails in application logs | Log a user id; redact emails (also a security requirement) |
| Analytics vendor outside India/EU | Transfer assessment and contract safeguards; pseudonymise before sending |
| Users cannot delete their account | Self-service deletion with a 30-day hard delete |

## 3. Identifying privacy-related threats with LINDDUN

**LINDDUN** (KU Leuven DistriNet) is the privacy counterpart of STRIDE. Apply it per DFD element and flow:

| Category | Threat | Example | Typical control |
|---|---|---|---|
| **L**inking | Data items can be linked to learn more about a person | One device id sent to the ad SDK and the analytics vendor | Per-recipient pseudonyms, aggregation |
| **I**dentifying | A person can be identified from data that should be anonymous | Email in analytics events; "anonymous" dataset with ZIP + birth date | Pseudonymisation, k-anonymity, remove direct identifiers |
| **N**on-repudiation | A person cannot deny an action when they should be able to | Signed logs of who read which support article in a whistle-blower tool | Plausible deniability, minimal logging for sensitive actions |
| **D**etecting | Someone can tell that an item exists | "This email is already registered" on a health app reveals membership | Uniform responses |
| **D**ata disclosure | Excessive collection, storage, processing or sharing | Collecting date of birth with no purpose; keeping data forever | Minimisation, retention, encryption, access control |
| **U**nawareness (and unintervenability) | People do not know or cannot control what happens to their data | No notice, no consent record, no access or deletion | Transparency, consent management, data subject requests |
| **N**on-compliance | The processing breaks law, policy or contracts | No DPIA, no record of processing, unlawful transfer | Privacy governance, DPIA, records, contracts |

The **2023 LINDDUN update** merged Unawareness and Unintervenability and refined the threat trees (verify on linddun.org). **LINDDUN GO** is a card deck for fast workshops (like Elevation of Privilege for privacy); **LINDDUN PRO** is the systematic per-element method; **LINDDUN MAESTRO** adds more detail (verify).

## 4. Threat modeling privacy for your system

1. **Data inventory.** List each personal data item: category (personal, sensitive, identifier), purpose, legal basis, retention, source.
2. **DFD with privacy annotations.** Mark flows to third parties, cross-border transfers, analytics and logs.
3. **Apply LINDDUN** per element and flow (or play LINDDUN GO with the team).
4. **Screen for a DPIA** and run it if needed.
5. **Prioritise** by harm to people (not only to the company): sensitive data, scale, vulnerable groups.
6. **Write privacy requirements** as stories and `SEC:`/`PRIV:` criteria; add tests (no email in logs, purge job runs).
7. **Repeat on change,** like any agile threat model (new vendor, new data item, new purpose).

The [privacy-linddun-pia lab](labs/privacy-linddun-pia/README.md) does steps 1 to 4 and 6 as code.

## 5. Scenario: the fitness app and the ad SDK

A start-up in Bengaluru builds a fitness app. Version 1 sends the phone's advertising id to an ad network **and** to an analytics vendor, logs users' emails with their heart rate, keeps everything forever, and says "this email is already registered" on signup. Nothing is "hacked", yet a LINDDUN session finds 18 privacy threats: the two vendors can link profiles, logs identify people with health data, signup reveals who uses the app, and there is no retention, no deletion and no DPIA although health data at scale clearly needs one. Version 2 uses a different pseudonym per vendor, an age band instead of date of birth, logs without PII, a 12-month retention, self-service deletion and a completed DPIA. Most of the fixes were cheap because they were made at design time.

## 6. Common mistakes

- "We encrypt everything, so privacy is done." Encryption does not stop over-collection or linking.
- Treating pseudonymised data as anonymous. It is still personal data under GDPR.
- Logs and analytics forgotten in the data inventory.
- DPIA written after launch to satisfy an audit.
- Privacy requirements without tests.

## 7. Checklist

- [ ] I can explain the difference between a PIA and a DPIA and when a DPIA is required.
- [ ] I can expand LINDDUN and give one example per category.
- [ ] I can run the seven steps on a small system.
- [ ] I can turn a privacy threat into a testable requirement.

## References

- LINDDUN (linddun.org): LINDDUN GO, PRO, MAESTRO.
- GDPR Art. 25 (data protection by design) and Art. 35 (DPIA); EDPB/WP29 DPIA guidelines (WP248).
- India Digital Personal Data Protection Act 2023 and DPDP Rules 2025 (verify current text at meity.gov.in).
- NIST Privacy Framework 1.0; ISO/IEC 29134 (PIA guidelines).
- Repo: [cybersecurity-track risk management](../../cybersecurity-track/04-risk-management-and-iso27001/README.md).
