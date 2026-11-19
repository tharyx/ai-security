# Lab: InSpec-style compliance profile (and scaling it to a fleet)

**Course exercises:** [CDP 8] "Create a Inspec profile to create compliance checks for your organization" and "Use Inspec profile to scale compliance". Lessons: [lesson 04](../../04-compliance-as-code.md).

**Time:** 60 minutes. **Safety:** no Ruby, no InSpec, no SSH. Hosts are JSON "facts"; the 20-host fleet is generated with a fixed random seed.

## What it does

[profile/](profile) holds `inspec.yml` plus controls in a **YAML DSL** that mirrors InSpec: control id, `impact`, title, tags, `only_if`, `describe` with a `resource`, `its` and `should` / `should_not` plus a matcher (`eq`, `cmp`, `be_in`, `match`, `include`, `be_lte`, `be_gte`, `be_nil`). Resources: `sshd_config`, `package`, `service`, `file`, `kernel_parameter`, `user`, `json`, `os`.

[inspec_lite.py](inspec_lite.py) provides:

- `load_profile` and `check_profile` (like `inspec check`);
- `run_profile` over a facts dict: passed, failed or **skipped** (`only_if`), with the actual value in the message; a missing fact **fails closed**;
- `summarize`: plain and **risk-weighted** score, failures by severity (InSpec's own impact mapping);
- `to_inspec_json`: a report shaped like `inspec exec --reporter json`;
- **At scale**: `generate_fleet` (20 hosts, deterministic drift, every fifth host without Docker) and `scan_fleet` (per-host score, most common failing controls, failures by severity, hosts below a threshold).

The same control in real InSpec:

```ruby
control 'ssh-01' do
  impact 1.0
  title 'SSH root login is disabled'
  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end
```

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/inspec-compliance-profile/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/inspec-compliance-profile -v
```

1. Run the demo. Find the control that fails on the most hosts. Which would you fix first, and why (impact versus count)?
2. Write a new control in `controls/ssh.yml` for `PermitEmptyPasswords` (impact 1.0). Make `host_drifted.json` fail it.
3. Break the profile on purpose (impact 3, duplicate id) and run `check_profile`.
4. Change the fleet seed. Does the ranking change? Why does the fixed seed matter for tests?

## Expected output (real run, abridged)

```text
Profile acme-linux-baseline 1.0.0: 13 controls, check errors: []

== web-001 ==  {'passed': 13, 'failed': 0, 'skipped': 0, 'compliance_pct': 100.0, 'risk_weighted_pct': 100.0, 'failed_by_severity': {}}

== web-099 ==  {'passed': 2, 'failed': 11, 'skipped': 0, 'compliance_pct': 15.4, 'risk_weighted_pct': 13.5, 'failed_by_severity': {'high': 2, 'medium': 5, 'critical': 4}}
  FAIL [high] docker-01 Inter-container communication is off by default
       json(/etc/docker/daemon.json) icc should eq false  (got: True)
  FAIL [medium] docker-02 no-new-privileges is the daemon default
       json(/etc/docker/daemon.json) no-new-privileges should eq true  (got: (missing))
  FAIL [critical] docker-03 The Docker API is not exposed on plain TCP
       json(/etc/docker/daemon.json) hosts should_not include "tcp://0.0.0.0:2375"  (got: ['fd://', 'tcp://0.0.0.0:2375'])
  FAIL [critical] os-01 Insecure legacy packages are not installed
       package(telnet) installed should eq false  (got: True)
  FAIL [medium] os-02 IP forwarding is disabled
       kernel_parameter(net.ipv4.ip_forward) value should cmp 0  (got: 1)
  FAIL [critical] os-04 /etc/shadow is not readable by group or others beyond 0640
       file(/etc/shadow) mode should be_in ["0640", "0600", "0400", "0000"]  (got: 0644)
  FAIL [medium] os-05 No guest account
       user(guest) exists should eq false  (got: True)
  FAIL [high] os-06 auditd is enabled and running
       service(auditd) running should eq true  (got: False)
  FAIL [critical] ssh-01 SSH root login is disabled
       sshd_config PermitRootLogin should cmp "no"  (got: yes)
  FAIL [medium] ssh-03 SSH allows at most 4 authentication attempts
       sshd_config MaxAuthTries should be_lte 4  (got: 6)
  FAIL [medium] ssh-04 SSH does not offer CBC ciphers
       sshd_config Ciphers should_not match "cbc"  (got: aes128-cbc,aes256-gcm@openssh.com)

=== At scale: 20 fake hosts ===
Fleet of 20 hosts, average compliance 85.1%

  web-001   84.6%  ########   pass 11 fail  2 skip  0  os-04,os-05
  web-002   69.2%  ######     pass  9 fail  4 skip  0  docker-01,os-02,os-04,ssh-01
  web-003   84.6%  ########   pass 11 fail  2 skip  0  docker-01,ssh-04
...
```

## Run the real tool

InSpec or the license-free CINC Auditor: [real-tools/inspec-cinc.md](../../real-tools/inspec-cinc.md). InSpec 6+ needs a license key (verify).
