# Lesson 02: Ansible and Ansible security

> **Unofficial companion.** Verify tool and product names at the source. Ansible Tower is now **Ansible Automation Platform (AAP)**; **AWX** is its upstream open-source project (verify current names).

**Syllabus items:** [CDP 7] Introduction to Ansible; Benefits of Ansible; Push and Pull based configuration management systems; Modules, tasks, roles and Playbooks; labs *Docker and Ansible* and *Using Ansible to create Golden images and harden Infrastructure*. [CDE 6] Configuration management (Ansible) security; Users/Privileges/Keys – Ansible Vault vs Tower; Challenges with Ansible Vault in CI/CD pipeline; lab *Using Ansible to harden on-prem/cloud machines for PCI-DSS*.

## 1. Introduction to Ansible

Ansible is a configuration management and automation tool. You write YAML **playbooks**; the **control node** (your laptop or a CI runner) connects to **managed nodes** over SSH (or WinRM for Windows), copies small Python modules, runs them, and removes them. There is **no agent** on the managed hosts.

## 2. Benefits of Ansible

- **Agentless**: nothing extra to install, patch or secure on every host (one less attack surface than a long-running agent).
- **Human-readable YAML**: reviewers who are not programmers can read a playbook.
- **Idempotent modules**: `package`, `service`, `user`, `lineinfile`, `sysctl` change only what differs.
- **Huge module library** and collections: OS, cloud, Docker, network devices.
- **Check mode and diff**: `--check --diff` shows what would change. That is a drift detector.
- **One tool for many jobs**: hardening, deployment, orchestration, image provisioning (Packer calls it).

## 3. Push and pull based configuration management

| Model | How it works | Examples | Security trade-offs |
|---|---|---|---|
| **Push** | A central node connects to targets and applies the change when you run it. | Ansible (default), Salt (push mode) | Control node holds keys to everything (protect it). No inbound agent. Changes happen when you run, so hosts can drift in between. |
| **Pull** | An agent on each host fetches its config from a server on a schedule and applies it. | Puppet, Chef, Salt minion, `ansible-pull` | Continuous drift correction. Agents and the config server are extra attack surface; hosts need outbound access to the server. |

**DBA analogy.** Push is like a DBA running a patch script across all databases on Saturday. Pull is like Oracle Enterprise Manager compliance standards that keep re-checking all the time. You can mix: Ansible for provisioning plus `ansible-pull` or a scheduled AAP job to re-apply.

## 4. Modules, tasks, roles and playbooks

| Term | Meaning | Example |
|---|---|---|
| **Inventory** | The list of hosts and groups. | `docker_hosts` group |
| **Module** | A unit of work with a state (`state: present`). | `ansible.builtin.package`, `community.docker.docker_container` |
| **Task** | One call of a module with parameters and keywords (`become`, `no_log`, `when`, `notify`). | "Write hardened daemon.json" |
| **Play** | Which hosts get which tasks. | `hosts: docker_hosts` |
| **Playbook** | A YAML file with one or more plays. | `site.yml` |
| **Role** | A reusable folder: `tasks/`, `defaults/`, `handlers/`, `templates/`, `meta/`. | `hardening` role |
| **Collection** | Packaged roles, modules and plugins, installed from Galaxy or Automation Hub. | `community.docker` |
| **Handler** | A task that runs once at the end if notified (restart a service after a config change). | "Restart docker" |

Practical rules: use the **fully qualified module name** (`ansible.builtin.copy`), prefer modules over `shell`, make every task idempotent, put variables in `defaults/`, and keep roles small and testable.

### Lab: Docker and Ansible

[docker-and-ansible](labs/docker-and-ansible/README.md) gives you a Docker host playbook and a **playbook linter** that checks `become`, `no_log`, digest-pinned images, a hardened `daemon.json` and idempotency smells. It is a teaching twin of **ansible-lint** ([real-tools/ansible.md](real-tools/ansible.md)).

### Lab: golden image hardening

[ansible-golden-image-hardening](labs/ansible-golden-image-hardening/README.md) applies a hardening **role** (sshd, auditd, sysctl, users, packages, file modes) to a fake host, runs CIS-like checks before and after, and proves the role is **idempotent**.

## 5. Ansible security: users, privileges and keys

Ansible is powerful because it logs in everywhere. Protect that power.

| Topic | Good practice |
|---|---|
| **Users** | Connect as a normal named or service user (`remote_user: ansible`), **not root**. Give each automation context its own account. |
| **Privileges** | Use `become: true` only where needed, at task level when possible. Restrict `sudo` for the automation user to what it needs (not `NOPASSWD: ALL` if you can avoid it). Never ask for root over SSH. |
| **Keys** | Use SSH key pairs (or short-lived certificates from an SSH CA), one per environment, passphrase protected or in an agent. Never commit private keys. Rotate them. Disable password auth on targets. |
| **Control node** | It holds the keys and decrypts vault files: harden it, limit who can log in, patch it. It is the most valuable host in the estate. |
| **Host keys** | Keep `host_key_checking` on; pre-populate `known_hosts` instead of disabling checks. |
| **Logs** | Use `no_log: true` on tasks that touch secrets, because tasks print parameters in output and callbacks. |
| **Content** | Pin collection and role versions in `requirements.yml`, review third-party roles before use. |

## 6. Ansible Vault versus Tower (AAP / AWX)

| | **Ansible Vault** | **Tower / AAP / AWX** |
|---|---|---|
| What it is | A built-in command that encrypts files or single variables (AES-256) with a password. | A web UI, REST API and job engine for running Ansible with RBAC. AAP is the Red Hat product; AWX is upstream. |
| Secrets | Encrypted data in your repo. Everyone who decrypts needs the vault password. | **Credential store**: secrets are entered once, encrypted in its database, injected into jobs, and users can use a credential without seeing it. |
| Access control | None: anyone with the password sees the plaintext. | Roles, teams, organisations, job templates, approval workflows, audit log. |
| Good for | Small teams, encrypted variables in git, bootstrap. | Shared automation, separation of duties, scheduled runs, central logs. |

**DBA analogy.** Vault is a password-protected file; Tower/AAP is closer to an Oracle Wallet plus a controlled job scheduler: the operator can run the job but never read the password.

```text
ansible-vault encrypt_string 'value' --name 'registry_password'   # encrypts one variable (verify syntax for your version)
ansible-playbook site.yml --vault-id prod@prompt                    # prompt for the vault password
```

## 7. Challenges with Ansible Vault in a CI/CD pipeline

The hard part is not encryption, it is **the vault password**:

1. **Where does the password live?** In a CI secret variable (best of the weak options), never in the repo. A file such as `.vault_pass` committed by mistake defeats everything.
2. **It lands on the runner.** Scripts read it from an env var or temporary file. Use `--vault-password-file` pointing to a script that reads the variable, delete files after the job, and use ephemeral runners.
3. **One password for many secrets.** Everyone who runs the pipeline effectively has everything. Use separate **vault IDs** per environment (`dev`, `prod`) and different passwords.
4. **Rotation is painful.** Changing the password means `ansible-vault rekey` for every file and updating CI. No per-secret expiry, no audit of who read what.
5. **No dynamic secrets.** A vaulted database password is static and long-lived.
6. **Leaks via output.** Missing `no_log: true`, verbose mode (`-vvv`) or diff mode can print decrypted values into CI logs.
7. **Review blind spot.** Reviewers see ciphertext, so a changed secret looks like noise.

**The usual answer: integrate an external secrets manager.** Keep ciphertext in git only for bootstrap data; fetch real secrets at run time with a lookup plugin (for example HashiCorp Vault `community.hashi_vault` lookups, AWS/Azure/GCP secret lookups, or CyberArk/1Password plugins; verify names), using the pipeline's **short-lived identity** (OIDC, AppRole with a wrapped secret ID). Benefits: central audit, rotation, per-secret policy, dynamic credentials with TTLs. Details and a working mock are in [chapter 13](../13-secrets-management/README.md) and the [CMCPSE secrets-vault lab](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/secrets-vault/README.md).

## 8. Using Ansible to harden machines for PCI DSS

[ansible-pci-dss-hardening](labs/ansible-pci-dss-hardening/README.md) tags each hardening task with a stable key, maps keys to **PCI DSS v4.0.1** requirement numbers (hedged: confirm the numbering and wording in the PCI SSC library) and produces a coverage report that **shows the gaps** (anti-malware, file integrity monitoring, process requirements). Lesson 04 explains why a task is evidence, not proof.

## Practice

1. Run the linter lab, then remove `become` from the good playbook and re-run.
2. Write down, for your own CI system, where the vault password would live and who could read it.
3. Continue with [lesson 03: Packer](03-packer-golden-images.md).
