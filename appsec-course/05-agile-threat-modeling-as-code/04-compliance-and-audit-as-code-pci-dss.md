# Lesson 04: Compliance and Audit as Code (PCI DSS v4.0.1)

**Syllabus items covered:** [CTMP 3] "Compliance and Audit as Code", "Writing Compliance As Code for PCI-DSS".

**Time:** 1 hour plus lab. **Safety:** fictional systems and config files.

> **DBA analogy.** You already did compliance as code: a SQL script that checks `DBA_USERS` for default accounts that are still open, `DBA_PROFILES` for password limits and the audit settings, run every month and saved as evidence. Compliance as code is the same idea, version-controlled and run on every change instead of once a month.

## 1. What compliance as code and audit as code mean

| Term | Meaning | Output |
|---|---|---|
| **Compliance as code** | Each control of a standard (PCI DSS, CIS Benchmark, ISO 27001 Annex A, internal policy) is written as an automated, version-controlled **check** or **policy** | Pass/fail per control, in CI and in production |
| **Policy as code** | A policy engine decides at run time (admission controller, API gateway, Terraform plan check) | Allow/deny decisions |
| **Audit as code** | The **evidence** is produced automatically: what was checked, when, against which exact state, with which result, and who approved each exception | A signed or hashed evidence bundle the auditor can re-run |

Why it matters for threat modeling: many threats ("default admin account still enabled", "PAN stored unencrypted") are also compliance controls. A control written once as code serves the threat model, the pipeline and the auditor.

## 2. Tools

| Tool | What it checks | Notes (verify at source) |
|---|---|---|
| **InSpec / CINC Auditor** | Hosts, containers, cloud accounts via Ruby DSL profiles | InSpec 6+ needs a Chef licence key; CINC Auditor is the community build |
| **OpenSCAP + SCAP Security Guide** | Linux hosts against XCCDF profiles (CIS, STIG, some PCI DSS profiles) | Check available profile ids with `oscap info` |
| **OPA / Rego, Conftest** | Any JSON/YAML: Kubernetes, Terraform plans, app config | Same engine at run time (Gatekeeper) and in CI (Conftest) |
| **Checkov, Trivy (config), KICS** | IaC (Terraform/OpenTofu, CloudFormation, Kubernetes, Dockerfile) | Built-in policies, many mapped to CIS and PCI |
| **Ansible** | Enforces the hardened state; `--check` mode reports drift | See devsecops course chapter 08 |
| **Cloud native** | AWS Config conformance packs, Azure Policy, Google Cloud SCC | Vendor PCI DSS packs; check they target v4.0.1 |

The DevSecOps course teaches InSpec, OpenSCAP and Ansible PCI hardening: [chapter 08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md), [lesson 04 compliance as code](../../devsecops-course/08-iac-configuration-and-compliance-as-code/04-compliance-as-code.md) and the [Ansible PCI DSS lab](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md). This lesson focuses on writing the PCI rules and the evidence.

## 3. PCI DSS v4.0.1 in one page (for engineers)

- **Scope:** systems that store, process or transmit cardholder data (the CDE) and systems connected to it. Reducing scope (tokenisation, network segmentation) is the best control.
- **Version:** **v4.0.1** (June 2024) is current; v3.2.1 retired in March 2024; the "future-dated" v4.0 requirements became mandatory on **31 March 2025** (verify at PCI SSC).
- **12 principal requirements** in six goals: network security controls (1), secure configuration (2), protect stored account data (3), protect data in transit (4), malware (5), secure systems and software (6), restrict access by need to know (7), identify and authenticate (8), physical access (9), log and monitor (10), test regularly (11), policies and programmes (12).
- **Two ways to meet a requirement:** the **defined approach** (do what the requirement says) or the **customized approach** (meet the stated objective another way, with a targeted risk analysis and more evidence). **Compensating controls** still exist for documented constraints.
- **Requirement 6** expects secure development: training, secure coding, review, and protection of public web apps (6.4.2 automated technical solution such as a WAF; verify).

Requirements that map well to code (numbers as we understand v4.0.1; verify):

| Requirement | Control as code |
|---|---|
| 1.3.1 | Inbound traffic to the CDE restricted: security group or firewall default deny |
| 2.2.2 | No enabled vendor default accounts |
| 3.3.1.2 | Card verification code not stored after authorization |
| 3.4.1 | PAN masked when displayed (at most BIN and last four) |
| 3.5.1 | PAN unreadable wherever stored |
| 4.2.1 | Strong cryptography (TLS 1.2+) for PAN over open networks |
| 8.2.8 | Idle session timeout of 15 minutes or less |
| 8.3.4 | Lockout after no more than 10 attempts, for at least 30 minutes |
| 8.3.6 | Passwords at least 12 characters (8 if the system cannot support 12) |
| 8.4.2 | MFA for all access into the CDE |
| 10.2.1, 10.5.1, 10.6.1 | Audit logs on, kept 12 months (3 months immediately available), clocks synchronised |
| 11.3.1, 11.5.2 | Internal scans every three months; change detection (FIM) |

## 4. Writing compliance as code for PCI DSS

A rule has five parts: **id**, **requirement reference**, **where to look** (path into config, resource attribute, command output), **expected value** and **severity**. Keep rules as **data** or in a policy language, not as ad-hoc scripts, so they can be reviewed and re-used:

```json
{"id": "PCI-AUTH-02", "requirement": "8.3.4", "title": "Lockout after no more than 10 invalid attempts",
 "path": "auth.lockout_attempts", "op": "between", "expected": [1, 10]}
```

Rules for the engine:

1. **Missing means fail.** A setting that is not present is not compliant.
2. **No `eval`.** A fixed set of operators (or a sandboxed policy language like Rego) so a rule file cannot run code.
3. **Exceptions are data too:** per system, with reason, owner and expiry. Expired = fail.
4. **Map each rule** to the requirement and, where useful, to the threat model finding and ASVS id.

## 5. Audit as code: evidence an auditor can trust

An auditor (QSA) wants to know: **what** was checked, **when**, **against which state**, with **which result**, and **who approved exceptions**. Audit as code produces that automatically:

- a results file per run (JSON), stored as a build artifact or in an evidence store with retention;
- a **hash of the exact configuration** checked, so a later change is detectable (the lab's `verify_evidence`);
- run metadata: tool version, rule set version (git commit), timestamp, system id;
- links to waivers and their approvals.

The lab [pci-compliance-as-code](labs/pci-compliance-as-code/README.md) implements all four ideas.

## 6. Scenario: the audit week that did not happen

A payments team used to spend a week before each assessment collecting screenshots. They moved 40 technical checks into a Conftest policy set and an InSpec profile tagged with PCI requirement numbers. Every merge request runs the policies on the Terraform plan; every night the profile runs against production and stores a JSON report with the config hash. During the assessment the QSA picked five requirements, the team showed the rule, the last 90 days of results and two time-boxed waivers. The QSA still interviewed people and sampled processes (requirement 12 is not code), but the technical evidence took one afternoon.

## 7. Common mistakes

- Treating a green scan as "PCI compliant". Many requirements are processes and people.
- Checks that pass when a setting is missing.
- Waivers in email with no expiry.
- Mapping to old v3.2.1 numbers. Re-map to v4.0.1.
- Evidence that cannot be tied to a specific state and time.

## 8. Checklist

- [ ] I can define compliance, policy and audit as code.
- [ ] I can name four tools and what each checks.
- [ ] I can write a PCI DSS rule with requirement id, path, operator and expected value.
- [ ] I can explain the customized approach and compensating controls in one sentence each.

## References

- PCI SSC document library: PCI DSS v4.0.1 and the summary of changes (verify).
- InSpec / CINC Auditor, OpenSCAP and SCAP Security Guide, Open Policy Agent and Conftest documentation.
- Repo: [devsecops-course chapter 08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md).
