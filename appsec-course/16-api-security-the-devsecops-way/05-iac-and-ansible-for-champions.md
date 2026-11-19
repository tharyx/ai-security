# Lesson 05: Infrastructure as Code and Its Security, with Ansible (summary and links)

**Syllabus items covered:** all of [CSC 6] "Infrastructure as Code and Its Security".

**Time:** 30 minutes for this summary; the linked devsecops lessons and labs take about a day.

> **Already taught in depth.** [devsecops ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md) covers IaC, Ansible, hardening, Packer and compliance as code, with offline labs (an Ansible playbook linter, golden-image hardening, PCI DSS hardening). This lesson summarises it for a security champion and points to the labs. No new lab was added here because those labs already cover each syllabus exercise.

## 1. Infrastructure as Code and its benefits

IaC describes servers, networks and services in **versioned files** instead of manual clicks. Benefits: repeatability (same result every time), speed, **reviewability** (pull requests for infrastructure), drift detection, disaster recovery (rebuild from code), documentation, and **security scanning before deployment**. Risks: a misconfiguration is copied everywhere; secrets in templates; state files that contain secrets; over-privileged pipeline credentials. Full lesson: [devsecops ch08 lesson 01 section 1](../../devsecops-course/08-iac-configuration-and-compliance-as-code/01-iac-and-configuration-management.md#1-what-is-infrastructure-as-code-and-its-benefits); IaC security: [section 4](../../devsecops-course/08-iac-configuration-and-compliance-as-code/01-iac-and-configuration-management.md#4-security-of-iac-itself).

## 2. Platform + infrastructure definition + configuration management

Three layers: the **platform** (cloud, virtualisation, Kubernetes), the **infrastructure definition** (what exists: VMs, networks, databases; Terraform/OpenTofu, CloudFormation, Bicep, Pulumi) and **configuration management** (what is installed and how it is configured inside: Ansible, Chef, Puppet, Salt). Immutable infrastructure (golden images with Packer, containers) reduces configuration drift. Full lesson: [devsecops ch08 section 2](../../devsecops-course/08-iac-configuration-and-compliance-as-code/01-iac-and-configuration-management.md#2-platform--infrastructure-definition--configuration-management).

## 3. Introduction to Ansible

Ansible is an **agentless** configuration management and automation tool: a control node connects over **SSH** (WinRM for Windows) and runs **modules** on managed hosts listed in an **inventory**, following **playbooks** written in YAML. It is idempotent: running twice should not change a host that is already correct. Ansible Tower is now **Ansible Automation Platform**; **AWX** is the upstream project. Full lesson: [devsecops ch08 lesson 02](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md#1-introduction-to-ansible).

## 4. Benefits of Ansible

No agent to install or patch; simple YAML; large module and collection ecosystem (Ansible Galaxy); idempotency; works for Linux, Windows, network devices and clouds; good for hardening at scale and for compliance remediation. Full lesson: [devsecops ch08 section 2](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md#2-benefits-of-ansible).

## 5. Modules, tasks, roles, and playbooks

- **Module:** a unit of work (`ansible.builtin.package`, `user`, `template`, `service`, `lineinfile`).
- **Task:** one call to a module with arguments.
- **Play / playbook:** a YAML file mapping hosts to ordered tasks; plays can use `become` for privilege escalation.
- **Role:** a reusable directory structure (tasks, handlers, templates, defaults, vars) such as a hardening role.
- **Collections:** packaged roles and modules (for example `devsec.hardening`; verify current names).

Full lesson: [devsecops ch08 section 4](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md#4-modules-tasks-roles-and-playbooks).

## 6. Tools and services that help to achieve IaC

| Need | Tools (Nov 2026; verify) |
|---|---|
| Provisioning | Terraform (BSL) / OpenTofu, Pulumi, CloudFormation, Bicep, Crossplane |
| Configuration | Ansible / AAP / AWX, Chef, Puppet, Salt |
| Images | Packer, Dockerfiles, buildpacks |
| Scanning IaC | Checkov, KICS, Trivy (`trivy config`), tfsec (merged into Trivy), ansible-lint, Terrascan |
| Policy as code | OPA/Rego with Conftest, Sentinel (HashiCorp), Kyverno (Kubernetes) |
| Compliance as code | InSpec/CINC Auditor (InSpec 6+ needs a licence key), OpenSCAP |
| GitOps | Argo CD, Flux, Atlantis (Terraform PR automation) |

Full lesson: [devsecops ch08 section 3](../../devsecops-course/08-iac-configuration-and-compliance-as-code/01-iac-and-configuration-management.md#3-tools-and-services-that-help-achieve-iac).

## 7. Working with Ansible

Typical flow: write an inventory, test connectivity (`ansible all -m ping`), run ad-hoc commands, write a playbook, run with `--check --diff` first, then for real; lint with `ansible-lint`. Security: SSH keys not passwords, a dedicated automation user with narrow `sudo`, **Ansible Vault** or an external secret manager for secrets, `no_log: true` on tasks that handle secrets. Lab: [devsecops ch08 docker-and-ansible](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/README.md) (a playbook security linter); lesson: [ch08 section 5](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md#5-ansible-security-users-privileges-and-keys).

## 8. Using Ansible to harden infrastructure

Apply CIS/STIG-style baselines with roles: SSH hardening (no root login, key-only), kernel parameters (sysctl), auditd, file permissions, removing unused services and packages, firewall rules, automatic security updates; then **verify** with InSpec/OpenSCAP so hardening is proven, not assumed. Labs: [ansible-golden-image-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-golden-image-hardening/README.md), [ansible-pci-dss-hardening](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/ansible-pci-dss-hardening/README.md); lesson: [ch08 section 8](../../devsecops-course/08-iac-configuration-and-compliance-as-code/02-ansible-and-ansible-security.md#8-using-ansible-to-harden-machines-for-pci-dss).

## 9. Working with Ansible playbooks

Write playbooks that are idempotent (`creates`, `changed_when`, `state: present`), use variables and templates, handlers for restarts, tags for partial runs, and roles for reuse. Review playbooks like code: no plaintext secrets, `become` only where needed, pinned image/package versions, `validate_certs: true`. Lab: [devsecops ch08 docker-and-ansible](../../devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/README.md) (its rule table is a review checklist).

## 10. Scenario: the copy-pasted security group

A team's Terraform module for "internal API servers" opens port 22 to `0.0.0.0/0` "for debugging". Twelve teams reuse the module. A Checkov rule in the pipeline would have blocked the first merge request; instead an external scan finds 140 SSH ports open. The fix is one line in the module, one pipeline rule for every IaC repo, and an Ansible hardening role that disables password SSH as a second layer. For an Oracle DBA: this is like a bad `init.ora` template copied to every database.

## 11. Checklist

- [ ] I can list five benefits and four risks of IaC.
- [ ] I can explain platform vs infrastructure definition vs configuration management.
- [ ] I can define module, task, play, playbook, role and collection.
- [ ] I can name IaC scanning and policy tools.
- [ ] I have done at least one devsecops ch08 Ansible lab.

## References

- Repo: [devsecops ch08](../../devsecops-course/08-iac-configuration-and-compliance-as-code/README.md) and its [Ansible real-tools guide](../../devsecops-course/08-iac-configuration-and-compliance-as-code/real-tools/ansible.md).
- Ansible docs (playbooks, roles, Vault, ansible-lint); CIS Benchmarks; OpenTofu and Checkov docs.
