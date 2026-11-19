# Lab: Ansible hardening for PCI DSS (requirement mapping and coverage report)

**Course exercise:** [CDE 6] "Using Ansible to harden on-prem/cloud machines for PCI-DSS". Lessons: [lesson 02 section 8](../../02-ansible-and-ansible-security.md), [lesson 04 section 6](../../04-compliance-as-code.md).

**Time:** 40 minutes. **Safety:** YAML fixtures only.

> **Hedge.** Requirement numbers target **PCI DSS v4.0.1**. The titles in [pci_mapping.yml](fixtures/pci_mapping.yml) are short paraphrases, not the standard's text. **Confirm numbering and wording in the PCI SSC document library and with your QSA.** Coverage here is not a compliance statement.

## What it does

[pci_mapper.py](pci_mapper.py):

- reads a hardening playbook whose tasks carry stable **tags** ([fixtures/pci_hardening_playbook.yml](fixtures/pci_hardening_playbook.yml));
- reads a mapping file that connects each tag to requirement ids with a strength, `direct` or `supporting`;
- validates the mapping (unknown requirement ids, bad strengths);
- produces a coverage report: **covered** (a direct task), **partial** (only supporting), **gap** (nothing); and lists tasks that map to nothing.

The gaps are the point: anti-malware (5.2.1), change detection (11.5.2) and the access control model (7.2.1) are not fixed by a hardening role.

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening -v
```

1. Run the demo and list the gaps. For each, name the control that would fill it (AV/EDR, AIDE or Wazuh FIM, policy).
2. Delete the `time_sync` task from the playbook: 10.6.1 becomes a gap.
3. Add an AIDE install task, tag it, and map it to 11.5.2 as `supporting` (why not `direct`?).
4. Add a mapping to a requirement id that is not in the catalogue and watch it be rejected.

## Expected output (real run)

```text
PCI mapping coverage (PCI DSS v4.0.1 (verify at source))
covered 11, partial 1, gap 4  -> 68.8% directly covered

  GAP     2.2.1     Configuration standards are defined and applied to system comp (needs another control or a process)
  OK      2.2.2     Vendor default accounts are managed (changed, removed or disab (1 direct, 0 supporting)
  OK      2.2.4     Only necessary services, protocols, daemons and functions are  (1 direct, 0 supporting)
  OK      2.2.5     Insecure services, protocols or daemons are justified and miti (1 direct, 0 supporting)
  OK      2.2.6     System security parameters are configured to prevent misuse    (2 direct, 0 supporting)
  OK      2.2.7     Non-console administrative access is encrypted with strong cry (1 direct, 0 supporting)
  GAP     5.2.1     Anti-malware solution deployed on system components at risk    (needs another control or a process)
  PARTIAL 6.3.3     Security patches installed within the defined time frames      (0 direct, 1 supporting)
  GAP     7.2.1     Access control model defined (need to know, least privilege)   (needs another control or a process)
  OK      8.2.6     Inactive user accounts removed or disabled within 90 days      (1 direct, 1 supporting)
  OK      8.3.4     Account lockout after a limited number of invalid attempts     (1 direct, 1 supporting)
  OK      8.3.6     Password minimum length and complexity (length 12 where suppor (1 direct, 0 supporting)
  OK      10.2.1    Audit logs are enabled and active for all system components    (1 direct, 1 supporting)
  OK      10.2.1.2  Audit logs capture all actions taken by administrative access  (1 direct, 0 supporting)
  OK      10.6.1    System clocks and time are synchronised using time-synchronisa (1 direct, 0 supporting)
  GAP     11.5.2    A change-detection mechanism (for example file integrity monit (needs another control or a process)

Tasks with no requirement mapping: Install a text editor for the admins

Coverage here means 'a task implements or supports the technical part'. It is not a compliance statement. Verify requirement numbers and wording at the PCI SSC library; ask your QSA.
```

## Run the real tool

Run the real Ansible role, then verify with an InSpec/CINC profile tagged with the same requirement ids, or an OpenSCAP PCI-DSS profile (see [real-tools/openscap.md](../../real-tools/openscap.md)).
