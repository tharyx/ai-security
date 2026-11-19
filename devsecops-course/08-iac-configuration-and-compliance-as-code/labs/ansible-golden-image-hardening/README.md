# Lab: Ansible golden image hardening (role applier and CIS-like checks)

**Course exercise:** [CDP 7] "Using Ansible to create Golden images and harden Infrastructure". Lessons: [lesson 02](../../02-ansible-and-ansible-security.md), [lesson 03](../../03-packer-golden-images.md).

**Time:** 45 minutes. **Safety:** the "host" is a Python dict loaded from JSON. Nothing touches a real system.

## What it does

[fixtures/role/](fixtures/role) is a hardening role (tasks plus defaults) for sshd, auditd, sysctl, users, packages and file modes. [applier.py](applier.py):

1. Loads the role and a weak fake host ([host_weak.json](fixtures/host_weak.json)).
2. **Applies** each task with a tiny module simulator (`package`, `lineinfile`, `sysctl`, `copy`, `service`, `user`, `file`) and reports `changed` only when state really changes.
3. Runs **18 CIS-like checks** (our own wording; they mirror the idea of CIS controls, not the licensed text) before and after.
4. Proves **idempotency** (second run: 0 changes) and **drift correction** (change one sysctl, re-apply, exactly one change).

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening -v
```

1. Run the demo and read which checks fail before and pass after.
2. Edit `defaults/main.yml`: set `MaxAuthTries` to `9`. Which check fails after applying?
3. Add a package to `hardening_packages_absent` and a matching CIS-like check in `applier.py`.
4. In the real world the same role runs inside a Packer build (see the [Packer lab](../packer-ansible-golden-image/README.md)).

## Expected output (real run)

```text
BEFORE: score 5.6%  failed: ['CIS-SSH-01', 'CIS-SSH-02', 'CIS-SSH-03', 'CIS-SSH-04', 'CIS-SSH-05', 'CIS-PKG-01', 'CIS-PKG-02', 'CIS-AUD-01', 'CIS-AUD-02', 'CIS-SYS-01', 'CIS-SYS-02', 'CIS-SYS-03', 'CIS-SYS-04', 'CIS-USR-01', 'CIS-USR-02', 'CIS-USR-03', 'CIS-FS-01']

Apply run 1: 21 changed, 2 already correct
  changed: Install security packages [auditd]
  changed: Install security packages [chrony]
  changed: Remove insecure packages [telnet]
  changed: Remove insecure packages [rsh-server]
  changed: Harden sshd_config [PermitRootLogin]
  changed: Harden sshd_config [PasswordAuthentication]
  ...

AFTER:  score 100.0%  failed: []

Apply run 2 (idempotency): 0 changed, 23 already correct
After drift: 1 changed -> ['Kernel parameters [net.ipv4.ip_forward]']
```

## Run the real tool

`ansible-playbook --check --diff` and Molecule: [real-tools/ansible.md](../../real-tools/ansible.md). Verify with InSpec/CINC or OpenSCAP: [real-tools/inspec-cinc.md](../../real-tools/inspec-cinc.md), [real-tools/openscap.md](../../real-tools/openscap.md).
