# Lab: Post-exploitation through reverse shells: a detector, not an exploit

**Course exercise:** "Post Exploitation In APIs Through Reverse Shells". Lesson: [05 section 1](../../05-post-exploitation-and-graphql.md#1-post-exploitation-in-apis-through-reverse-shells). The API-world post-exploitation view continues in [chapter 13](../../../13-owasp-api-top-10-and-other-threats/03-post-exploitation-xss-and-cors.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** this repository does **not** contain reverse-shell code or one-liners. The lab reads fictional, structured telemetry (process and network events, like EDR/auditd/Falco/Sysmon output) with redacted command lines and documentation IP ranges (203.0.113.0/24, 198.51.100.0/24). Only test systems you own or have written permission to test.

## Goal

Build the defender's side: detect a reverse shell from process lineage, socket file descriptors, egress and command-line indicators, and show the prevention controls (default-deny egress, images without shells, non-root).

## Concept

After code execution (deserialization, command injection, SSTI), an attacker wants an interactive session. Inbound connections are usually blocked, so the compromised process connects **out** to the attacker and attaches a shell to that connection: a **reverse shell**. Its footprints:

| Rule | Signal | Real-world source |
|---|---|---|
| R1 lineage | Web/API runtime (gunicorn, java, node, php-fpm) spawns `sh`/`bash`/an interpreter | EDR process tree, Sysmon event 1, auditd `execve` |
| R2 socket fds | A shell whose stdin/stdout is a network socket | Falco rule for stdin/stdout redirected to a network connection |
| R3 egress | Shell or interpreter connects to an unknown external IP | Flow logs, firewall, Sysmon event 3 |
| R4 indicators | `/dev/tcp/`, netcat-family binary with `-e`, `pty.spawn` | Command-line logging (Sigma rules) |
| R5 prevention | Image ships a shell or netcat; container runs as root | Image scanning, admission policy |

## Steps

1. Run the demo. Three CRITICAL alerts, one MEDIUM. Is the MEDIUM (an image-resize job started by the app) a true positive? How would you tune it without losing R1 (allowlist expected child commands)?
2. Remove `10.0.0.0/8` from the egress allowlist: what happens to the database flow? This is why egress policy needs an inventory.
3. Add a fixture event where `powershell.exe` is spawned by `w3wp.exe` (IIS) and make R1 catch it.

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/reverse-shell-detector/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/reverse-shell-detector -q -p no:cacheprovider
```

## Expected output (real run)

```text
== Detection over simulated EDR/auditd telemetry ==
[CRITICAL] api-1 pid 300 'sh' (parent 'python3 app.py')
       R1 shell/interpreter spawned by server process python3 app.py
       R2 shell with stdin/stdout bound to a network socket
       R3 outbound 203.0.113.50:4444 not in egress allowlist
[CRITICAL] api-2 pid 401 'bash' (parent 'java')
       R1 shell/interpreter spawned by server process java
       R4 command-line indicator
       R3 outbound 203.0.113.77:443 not in egress allowlist
[CRITICAL] worker-1 pid 500 'ncat' (parent '')
       R4 command-line indicator
       R3 outbound 198.51.100.23:8443 not in egress allowlist
[MEDIUM] api-1 pid 600 'python3' (parent 'python3 app.py')
       R1 shell/interpreter spawned by server process python3 app.py

== Prevention: default-deny egress would have dropped ==
   api-1 pid 300 -> 203.0.113.50:4444
   api-2 pid 401 -> 203.0.113.77:443
   worker-1 pid 500 -> 198.51.100.23:8443

== Prevention: image review ==
   shop-api:1.4 (debian-based): ['R5 image shop-api:1.4 (debian-based) ships /bin/sh', 'R5 image shop-api:1.4 (debian-based) ships /bin/bash', 'R5 image shop-api:1.4 (debian-based) ships /usr/bin/ncat', 'R5 image shop-api:1.4 (debian-based) runs as root']
   shop-api:2.0 (distroless): ['clean']
```

## Run the real tool (hedged)

- **Falco** (CNCF) ships default rules for shells in containers and stdin/stdout redirection to network connections; run it in a test cluster and trigger alerts with the course's lab exercise.
- **Sigma** rules (converted for Sentinel/Splunk/Elastic) cover suspicious parent-child process pairs and reverse-shell command-line patterns; see the repo's [SIEM chapter](../../../../cybersecurity-track/06-siem-sentinel-splunk/README.md).
- Prevention: Kubernetes NetworkPolicy default-deny egress, distroless images, `readOnlyRootFilesystem`, seccomp `RuntimeDefault`, non-root users.

## What you learned

- Reverse shells are noisy in good telemetry: lineage plus socket plus egress is a strong signal.
- The cheapest prevention is no shell in the image and no outbound internet from app servers.
