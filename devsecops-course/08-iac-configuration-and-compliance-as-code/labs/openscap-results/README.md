# Lab: OpenSCAP results to a compliance score

**Course topic:** [CDP 8] "Manage compliance using Inspec/OpenScap at Scale". Lessons: [lesson 04 section 4](../../04-compliance-as-code.md).

**Time:** 30 minutes. **Safety:** XML fixtures only. No `oscap` is run. The parser rejects DOCTYPE and entity declarations.

## What it does

[scap_results.py](scap_results.py) parses an **ARF-like** file (a Benchmark with Rule definitions and a `TestResult` with one `rule-result` per rule) that mimics what `oscap xccdf eval --results-arf` writes, and:

- counts results (`pass`, `fixed`, `fail`, `error`, `unknown`, `notapplicable`, `notchecked`, `informational`);
- computes a **flat score** (a simplification of the XCCDF default model: pass and fixed succeed; fail, error and unknown fail; the others are excluded) and checks it against the score the file declares;
- computes a **severity-weighted score** (high 3, medium 2, low 1);
- lists failing rules worst first;
- **compares** a before and an after scan: improved, regressed, still failing.

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/openscap-results/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/openscap-results -v
```

1. Read the before report. Why is the severity-weighted score lower than the flat score?
2. Why is `notapplicable` (SELinux on a Debian-family host) excluded from the score?
3. Change a declared score in the XML by hand. What does `matches_declared` say, and why is that a useful tamper signal?
4. Add a `<!DOCTYPE` line and see the parser refuse the file.

## Expected output (real run, abridged)

```text
=== BEFORE remediation ===
Target app-01.example  profile standard
results: {'fail': 8, 'pass': 6, 'notapplicable': 1, 'notchecked': 1, 'error': 1, 'informational': 1}
flat score 40.0%  severity-weighted 34.38%  (declared 40.0, match True)
failed by severity: {'high': 4, 'medium': 4, 'low': 1}
Failing rules, worst first:
  [high  ] fail  file_permissions_etc_shadow: Verify Permissions on /etc/shadow
  [high  ] fail  package_telnet-server_removed: Uninstall the telnet server
  [high  ] fail  sshd_disable_empty_passwords: Disable SSH Access via Empty Passwords
  [high  ] fail  sshd_disable_root_login: Disable SSH Root Login
  [medium] fail  accounts_password_minlen_login_defs: Set Password Minimum Length in login.defs
  [medium] error package_aide_installed: Install AIDE
  [medium] fail  service_auditd_enabled: Enable auditd Service
  [medium] fail  sysctl_net_ipv4_ip_forward: Disable Kernel Parameter for IP Forwarding
  [low   ] fail  mount_option_tmp_nodev: Add nodev Option to /tmp

=== AFTER remediation ===
Target app-01.example  profile standard
results: {'pass': 13, 'fixed': 1, 'fail': 1, 'notapplicable': 1, 'notchecked': 1, 'informational': 1}
flat score 93.33%  severity-weighted 96.88%  (declared 93.33, match True)
failed by severity: {'low': 1}
Failing rules, worst first:
  [low   ] fail  mount_option_tmp_nodev: Add nodev Option to /tmp

=== Comparison ===
{'improved': ['accounts_password_minlen_login_defs', 'file_permissions_etc_shadow', 'package_aide_installed', 'package_telnet-server_removed', 'service_auditd_enabled', 'sshd_disable_empty_passwords', 'sshd_disable_root_login', 'sysctl_net_ipv4_ip_forward'], 'regressed': [], 'still_failing': ['mount_option_tmp_nodev'], 'delta_flat': 53.33}
```

## Run the real tool

`oscap xccdf eval` with the SCAP Security Guide content: [real-tools/openscap.md](../../real-tools/openscap.md).
