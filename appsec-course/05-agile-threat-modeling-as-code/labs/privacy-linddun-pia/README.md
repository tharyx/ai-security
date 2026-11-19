# Lab: Privacy threat modeling with LINDDUN and a PIA/DPIA screening

**Course exercises:** [CTMP 3] "Privacy Impact Assessments and Security Requirements", "Identifying Privacy Related Threats", "Threat Modeling Privacy for your system". Lesson: [05 Privacy threat modeling](../../05-privacy-threat-modeling-linddun-and-pia.md).

**Time:** 50 minutes. **Tests:** 9, all offline. **Safety:** a fictional fitness app described in JSON. No real personal data. Only test systems you own or have written permission to test.

> **Hedge.** The DPIA screening uses the EDPB/WP29 "two or more criteria" rule of thumb. It is not legal advice. Check GDPR Art. 35, your regulator's DPIA list and, in India, the **DPDP Act 2023** and the **DPDP Rules notified in November 2025** (phased in, verify dates) with your privacy team.

## Goal

Model a system's personal data and flows as data, run LINDDUN-style rules over it, decide whether a DPIA is needed, and turn the threats into **privacy requirements** for the backlog. Compare the first design with a privacy-by-design version.

## Concept

[privacy.py](privacy.py):

| LINDDUN category | Example rule in the lab |
|---|---|
| **L**inking | one persistent id (`device_id`) is sent to two third parties, so they can join profiles |
| **I**dentifying | email sent to analytics or logs without pseudonymisation |
| **N**on-repudiation (unwanted) | signed, identity-linked logs of sensitive actions |
| **D**etecting | signup or reset reveals whether an email has an account |
| **D**ata disclosure | data with no purpose (minimisation), no retention, personal data sent unencrypted |
| **U**nawareness (and unintervenability) | no consent record, no access or deletion requests |
| **N**on-compliance | no record of processing, transfer abroad without safeguards, DPIA needed but not done |

`dpia_screening()` counts the EDPB-style criteria (profiling, monitoring, sensitive data, large scale, and so on). `privacy_requirements()` maps each category found to a `PRIV-0x` requirement.

Fixtures: [fitness_app_v1.json](fixtures/fitness_app_v1.json) (first design) and [fitness_app_v2.json](fixtures/fitness_app_v2.json) (after the LINDDUN session: per-recipient pseudonym, age band instead of date of birth, retention set, logs without PII, DSAR support, transfer safeguards, DPIA done).

## Steps

```text
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/privacy-linddun-pia/demo.py
.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code/labs/privacy-linddun-pia -q -p no:cacheprovider
```

1. Run the demo and compare v1 (18 threats) with v2 (none).
2. In a copy of v1, replace `date_of_birth` with `age_band` and give it a purpose and a retention. Which threats disappear?
3. Add `"vulnerable_subjects": true` to v2's `processing` block (the app adds a children's plan). The DPIA is still required; what else would you add to the requirements?
4. For your own system, list five data items and three flows in the same JSON shape and run the rules.

## Expected output (real run of demo.py)

```text
== FitTrack v1 (first design) ==
  DPIA required: True (criteria met: Evaluation, scoring or profiling, Systematic monitoring, Sensitive (special category) data, Processing at large scale)
  LINDDUN summary: {'Linking': 1, 'Identifying': 3, 'Detecting': 1, 'Data disclosure': 6, 'Unawareness': 2, 'Non-compliance': 3}
  [Linking] device_id: same id shared with ['AdNetwork', 'Analytics SaaS']: profiles can be joined
  [Identifying] app to ad SDK: ['device_id'] sent for analytics in identifiable form
  [Identifying] app to analytics: ['device_id', 'email'] sent for analytics in identifiable form
  [Identifying] API to logs: ['email', 'heart_rate'] sent for logging in identifiable form
  [Detecting] signup/reset: responses reveal whether an email has an account
  [Data disclosure] email: no retention period: kept forever
  [Data disclosure] device_id: no retention period: kept forever
  [Data disclosure] heart_rate: no retention period: kept forever
  [Data disclosure] date_of_birth: collected without a stated purpose (minimisation)
  [Data disclosure] date_of_birth: no retention period: kept forever
  [Data disclosure] API to logs: personal data sent without encryption
  [Unawareness] user: consent is not recorded
  [Unawareness] user: users cannot see or delete their data
  [Non-compliance] organisation: no record of processing activities
  [Non-compliance] app to analytics: transfer abroad without checked safeguards
  [Non-compliance] organisation: DPIA required but not done
  Privacy requirements for the backlog:
   - PRIV-01 Use per-recipient pseudonymous ids; never share one persistent id with several parties
   - PRIV-02 Pseudonymise or aggregate data used for analytics and logs
   - PRIV-04 Give the same response whether or not an account exists
   - PRIV-05 Collect only data with a stated purpose, set retention, encrypt in transit
   - PRIV-06 Show a clear notice, record consent, support access, correction and deletion requests
   - PRIV-07 Keep a record of processing, a DPIA when required, and safeguards for transfers abroad

== FitTrack v2 (privacy by design) ==
  DPIA required: True (criteria met: Sensitive (special category) data, Processing at large scale)
  LINDDUN summary: no threats found
```

## Run the real tool (hedged)

- **LINDDUN** (linddun.org): the threat trees, the **LINDDUN GO** card deck for workshops and **LINDDUN PRO** for systematic analysis. Free to download (verify).
- **DPIA templates:** your regulator's template (for example the UK ICO template) or the CNIL **PIA** software (open source, verify it is still maintained).
- **OWASP Threat Dragon** and other tools let you add custom (privacy) threat types to elements; see [chapter 06](../../../06-threat-model-tools-reporting-and-ai/README.md).

## What you learned

- Security protects data from attackers; privacy also protects people from the system's **intended** use of data.
- LINDDUN gives privacy the same "per element, per flow" discipline STRIDE gives security.
- A PIA/DPIA turns into concrete requirements (minimise, pseudonymise, retain, inform, allow deletion), which go into the backlog like any other story.
