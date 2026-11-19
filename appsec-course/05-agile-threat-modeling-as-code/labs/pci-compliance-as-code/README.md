# Lab: Compliance as code and audit as code for PCI DSS v4.0.1

**Course exercises:** [CTMP 3] "Writing Compliance As Code for PCI-DSS", "Compliance and Audit as Code". Lesson: [04 Compliance and audit as code](../../04-compliance-and-audit-as-code-pci-dss.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** JSON config fixtures of a fictional payments API. Only test systems you own or have written permission to test.

> **Hedge.** Requirement numbers target **PCI DSS v4.0.1** as we understand it, and titles are short paraphrases. Confirm numbering and wording in the PCI SSC document library and with your QSA. Passing these checks is not a compliance statement.

## Goal

Write PCI DSS controls as **rules in data**, evaluate them against a system's configuration, handle compensating controls as **expiring waivers**, and produce an **evidence bundle** an auditor can verify.

## Concept

- [fixtures/pci_rules.json](fixtures/pci_rules.json): 16 rules. Each has a rule id, the PCI DSS requirement number, a title, a dotted `path` into the config, an operator and an expected value.
- [pci_rules.py](pci_rules.py): a fixed set of operators (`eq`, `gte`, `lte`, `between`, `in`, `matches`, `no_item_matches`). No `eval`, so a rule file cannot run code. A **missing** setting is a failure, never a pass.
- **Waivers** ([fixtures/waivers.json](fixtures/waivers.json)) are per system and need a reason, an owner and an expiry date. An expired or incomplete waiver fails.
- **Audit as code:** `evidence_bundle()` stores the results with a SHA-256 of the exact config that was checked. `verify_evidence()` lets the auditor detect a config that changed after the scan.

How this differs from the DevSecOps course: its [Ansible PCI DSS hardening lab](../../../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md) maps **hardening tasks** to requirements (what we *do*). This lab **checks the resulting state** (what is *true*), which is what InSpec, OPA/Conftest and cloud config rules do.

## Steps

```text
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/pci-compliance-as-code/demo.py
.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code/labs/pci-compliance-as-code -q -p no:cacheprovider
```

1. Run the demo. The weak config fails all 16 rules; the hardened config passes with one documented waiver.
2. In a copy of the hardened config, set `lockout_attempts` to 11. Requirement 8.3.4 says no more than 10, so the rule fails.
3. Remove the `owner` from the waiver. The waiver is ignored: no owner, no exception.
4. Add a rule of your own, for example `{"path": "storage.pan_display_mask", "op": "matches", "expected": "last4|bin_and_last4"}`.

## Expected output (real run of demo.py)

```text
== payments-api (first deploy) ==
  FAIL   1.3.1    Inbound traffic to the CDE is restricted (default deny)     observed=allow expected eq 'deny'
  FAIL   2.2.2    Vendor default accounts are disabled or changed             observed=[{'name': 'admin', 'default':  expected no_item_matches {'default': True, 'enabled': True}
  FAIL   3.3.1.2  Card verification code is not stored after authorization    observed=True expected eq False
  FAIL   3.4.1    PAN is masked when displayed (at most BIN and last four)    observed=full expected in ['last4', 'bin_and_last4']
  FAIL   3.5.1    PAN is unreadable wherever it is stored                     observed=False expected eq True
  FAIL   4.2.1    Strong cryptography for PAN over open, public networks      observed=1.0 expected in ['1.2', '1.3']
  FAIL   8.2.8    Idle sessions time out after 15 minutes or less             observed=60 expected between [1, 15]
  FAIL   8.3.4    Lockout after no more than 10 invalid attempts              observed=0 expected between [1, 10]
  FAIL   8.3.4    Lockout lasts at least 30 minutes (or until identity confi  observed=0 expected gte 30
  FAIL   8.3.6    Passwords are at least 12 characters                        observed=8 expected gte 12
  FAIL   8.4.2    MFA for all access into the CDE                             observed=False expected eq True
  FAIL   10.2.1   Audit logs are enabled and active                           observed=False expected eq True
  FAIL   10.5.1   Audit log history kept for at least 12 months               observed=30 expected gte 365
  FAIL   10.6.1   System clocks are synchronised                              observed=False expected eq True
  FAIL   11.3.1   Internal vulnerability scans at least every three months    observed=365 expected between [1, 90]
  FAIL   11.5.2   A change-detection mechanism (FIM) is deployed              observed=False expected eq True
  gate exit code: 1

== payments-api (hardened) ==
  PASS   1.3.1    Inbound traffic to the CDE is restricted (default deny)   
  PASS   2.2.2    Vendor default accounts are disabled or changed           
  PASS   3.3.1.2  Card verification code is not stored after authorization  
  PASS   3.4.1    PAN is masked when displayed (at most BIN and last four)  
  PASS   3.5.1    PAN is unreadable wherever it is stored                   
  PASS   4.2.1    Strong cryptography for PAN over open, public networks    
  PASS   8.2.8    Idle sessions time out after 15 minutes or less           
  PASS   8.3.4    Lockout after no more than 10 invalid attempts            
  PASS   8.3.4    Lockout lasts at least 30 minutes (or until identity confi
  WAIVED 8.3.6    Passwords are at least 12 characters                        observed=8 compensating control until 2027-03-31: legacy HSM admin cons
  PASS   8.4.2    MFA for all access into the CDE                           
  PASS   10.2.1   Audit logs are enabled and active                         
  PASS   10.5.1   Audit log history kept for at least 12 months             
  PASS   10.6.1   System clocks are synchronised                            
  PASS   11.3.1   Internal vulnerability scans at least every three months  
  PASS   11.5.2   A change-detection mechanism (FIM) is deployed            
  gate exit code: 0

== Audit as code: evidence bundle (first lines) ==
{
  "system": "payments-api (hardened)",
  "checked_at": "2026-11-19T10:00:00Z",
  "standard": "PCI DSS v4.0.1 (subset; verify at PCI SSC)",
  "config_sha256": "2c266668aa5de3142063c22b088510ba596429e4477f5ed645ccf4be9f5a7d5d",
  "summary": {
    "PASS": 15,
    "FAIL": 0,
    "WAIVED": 1
  evidence matches current config: True
  after a silent config change:    False

== The waiver expires ==
   PCI-AUTH-04 FAIL (expected gte 12; waiver expired on 2027-03-31)
   gate exit code: 1
```

## Run the real tool (hedged)

- **InSpec / CINC Auditor:** write a profile with controls tagged by PCI requirement (`tag pci: ['8.3.6']`) and run `inspec exec profile -t ssh://host --reporter json:out.json`. InSpec 6+ needs a Progress Chef licence key; CINC Auditor is the community build (verify). See [devsecops-course lesson 04 compliance as code](../../../../devsecops-course/08-iac-configuration-and-compliance-as-code/04-compliance-as-code.md).
- **OPA / Conftest:** write Rego policies over JSON or YAML config and run `conftest test config.json -p policy/` in CI.
- **OpenSCAP** with the SCAP Security Guide has PCI DSS profiles for some Linux distributions (verify the profile id with `oscap info`).
- **Cloud:** AWS Config conformance packs, Azure Policy and Google Cloud Security Command Center have PCI DSS mappings (verify the v4.0.1 versions).

## What you learned

- Compliance as code = controls as versioned, testable rules; audit as code = repeatable evidence tied to the exact state checked.
- A missing setting and an expired exception must fail; otherwise compliance decays silently.
- Compensating controls are allowed by PCI DSS but are documented, owned and time-boxed.
