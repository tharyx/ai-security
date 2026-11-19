# Lab: Docker and Ansible (playbook linter)

**Course exercise:** [CDP 7] "Docker and Ansible". Lessons: [lesson 02](../../02-ansible-and-ansible-security.md).

**Time:** 40 minutes. **Safety:** YAML fixtures only. Nothing connects to a host or runs Ansible or Docker. The "secrets" are fake canaries.

## What it does

[playbook_linter.py](playbook_linter.py) reads an Ansible playbook for a Docker host and reports:

| ID | Checks |
|---|---|
| ANS-001 | Privilege use: modules that need root run without `become` |
| ANS-002 | Tasks that handle passwords or tokens without `no_log: true` |
| ANS-003 | Docker images not pinned by digest (`:latest` is HIGH, a mutable tag is MEDIUM) |
| ANS-004 | `daemon.json` missing, or missing `no-new-privileges`, `icc=false`, `userland-proxy=false`, `live-restore`, log limits; exposed `tcp://` and `insecure-registries` |
| ANS-005 | Idempotency smells: `command`/`shell` without `creates`/`changed_when`, `>>` appends, `state: latest`, `lineinfile` without `regexp` |
| ANS-006 | World-writable modes, `validate_certs: false`, plain http downloads without a checksum |
| ANS-007 | Literal secrets in `vars` (a `!vault` value is accepted) |
| ANS-008 | `remote_user: root` |

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/docker-and-ansible -v
```

1. Run the demo: the good playbook passes, the bad one fails with every rule.
2. Remove `no_log: true` from the good playbook. Which rule fires?
3. Replace the digest with `:1.0`. Why is that MEDIUM and `:latest` HIGH?
4. Add `ansible.builtin.shell: "docker run ..."` to the good playbook and read the idempotency findings.
5. Think: which of these findings would `ansible-lint` also catch, and which only a policy you write?

## Expected output (real run, abridged)

```text
== playbook_docker_host.yml: PASS (0 finding(s)) ==
== playbook_docker_host_bad.yml: FAIL (26 finding(s)) ==
  [CRITICAL] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon listens on tcp://: an unauthenticated Docker API is remote root
  [CRITICAL] ANS-007 play[0].vars.registry_password: literal secret in vars: use !vault or a secrets manager lookup
  [HIGH    ] ANS-001 play[0]:Fetch a tool: get_url needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-001 play[0]:Install docker: apt needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-001 play[0]:Log in to the registry: docker_login needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-001 play[0]:Run nginx: docker_container needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-001 play[0]:Run the API with a mutable tag: docker_container needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-001 play[0]:Write daemon.json (exposes the API, weak settings): copy needs privileges but no become (set become: true on the task or play)
  [HIGH    ] ANS-002 play[0]:Log in to the registry: task handles a secret without no_log: true (it will print in logs and callbacks)
  [HIGH    ] ANS-003 play[0]:Run nginx: image nginx:latest is unpinned or :latest
  [HIGH    ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): insecure-registries allows plain http pulls (tampering)
  [HIGH    ] ANS-006 play[0]:Write daemon.json (exposes the API, weak settings): world-writable mode 0777
  [MEDIUM  ] ANS-003 play[0]:Run the API with a mutable tag: image registry.example/shop/api:1.4.2 uses a mutable tag: pin the digest (@sha256:...)
  [MEDIUM  ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon.json should set no-new-privileges=true
  [MEDIUM  ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon.json should set icc=false
  [MEDIUM  ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon.json should set userland-proxy=false
  [MEDIUM  ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon.json should set live-restore=true
  [MEDIUM  ] ANS-005 play[0]:Install curl the hard way: shell without creates/removes/changed_when is not idempotent
  [MEDIUM  ] ANS-005 play[0]:Install curl the hard way: a dedicated module exists for this action (package, service, user, docker_container)
  [MEDIUM  ] ANS-005 play[0]:Tune the kernel: shell without creates/removes/changed_when is not idempotent
  [MEDIUM  ] ANS-005 play[0]:Tune the kernel: appending with >> adds a line on every run: use lineinfile or the sysctl module
  [MEDIUM  ] ANS-006 play[0]:Fetch a tool: validate_certs is false: TLS is not verified
  [MEDIUM  ] ANS-006 play[0]:Fetch a tool: plain http download without a checksum
  [MEDIUM  ] ANS-008 play[0]: remote_user is root: connect as a normal user and use become
  [LOW     ] ANS-004 play[0]:Write daemon.json (exposes the API, weak settings): daemon.json should set log-driver and log-opts max-size (disk exhaustion)
  [LOW     ] ANS-005 play[0]:Install docker: state: latest changes the host on every run; use present and pin versions, upgrade deliberately
```

## Run the real tool

`ansible-lint` and `ansible-playbook --check --diff`: see [real-tools/ansible.md](../../real-tools/ansible.md). The lab linter is a teaching twin, not a replacement.
