# Real tools: Ansible and ansible-lint

> Hedged guide. Commands and option names change between releases: **verify at docs.ansible.com**. Practise only on machines you own. The labs in this chapter never need these tools.

## Install (control node)

```text
python -m pip install ansible ansible-lint
ansible --version
ansible-galaxy collection install community.docker
```

On Windows, use WSL for the control node (Ansible does not run natively as a control node). Managed Linux hosts need SSH and Python.

## Check a playbook before you run it

```text
ansible-lint playbook.yml                      # style, safety and idempotency rules
ansible-playbook playbook.yml --syntax-check
ansible-playbook playbook.yml --check --diff   # dry run: what would change?
```

`ansible-lint` has profiles from `min` to `production` (verify names). Its rules overlap with the lab linter: missing `become` is not one of them, but `no-changed-when`, `command-instead-of-module`, `risky-file-permissions`, `latest`, `fqcn` and `no-log-password` are (verify the current rule list with `ansible-lint -L`).

## Run

```text
ansible-playbook -i inventory.ini site.yml --limit docker_hosts
ansible-playbook site.yml --vault-id prod@prompt
```

Check mode on a schedule is a cheap **drift detector**: any "changed" is drift.

## Vault

```text
ansible-vault create group_vars/prod/vault.yml
ansible-vault encrypt_string 'a-value' --name 'registry_password'
ansible-vault rekey group_vars/prod/vault.yml
```

Do not commit vault password files. Read the password from the CI secret store at run time, or prefer an external secrets manager lookup (chapter 13).

## Tower, AAP and AWX

- **Ansible Automation Platform (AAP)** is Red Hat's product (formerly Ansible Tower).
- **AWX** is the upstream open-source project; its release cadence and install method (Kubernetes operator) have changed over time. Verify the current status and supportability before relying on it.

## Role testing

Molecule (with a Docker driver) runs a role in a throwaway container, converges it twice and checks idempotency (second run must report zero changes). That is the real-tool twin of the lab's idempotency test.
