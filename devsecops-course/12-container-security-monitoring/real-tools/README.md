# Real tools for chapter 12 (hedged guides)

Everything in the labs is an offline simulation. This page says what to run for real. Tool status and flags change: **verify at the source**. Use only on systems you own.

## Tool table

| Job | Tool | Status note (Nov 2026, verify) | Lab |
|---|---|---|---|
| Linux audit trail | auditd (`auditctl`, `ausearch`, `augenrules`) | part of the Linux audit framework | [auditd-docker](../labs/auditd-docker/README.md) |
| Runtime detection | Falco | CNCF graduated; eBPF probe | [falco](../labs/falco-runtime-rules/README.md) |
| Runtime detection (eBPF) | Tracee (Aqua) | open source | [tracee](../labs/tracee-runtime/README.md) |
| SIEM/XDR | Wazuh with docker-listener wodle | open source | [wazuh](../labs/wazuh-docker-monitoring/README.md) |
| Log shipping | Docker logging drivers, Fluent Bit, Vector | pick one pipeline, test back-pressure | [01 section 2](../01-monitoring-logs-and-incident-response.md) |
| Sandbox / prevention | seccomp, AppArmor, SELinux, gVisor, Kata | see chapter 11 | [11 lab](../../11-defending-containers-at-scale/labs/seccomp-apparmor-custom-policy/README.md) |

## Docker events and logs

```text
docker events --format '{{json .}}' --filter type=container
docker logs --since 1h --timestamps CONTAINER
docker info --format '{{.LoggingDriver}}'
```

## Falco

```text
sudo falco -r /etc/falco/falco_rules.yaml -r my_rules.yaml
falco --validate my_rules.yaml      # syntax check; verify the flag for your version
```

## auditd

```text
sudo augenrules --load && sudo auditctl -l
sudo ausearch -k docker-config -ts today -i
```

## Safety note

Runtime tools run with high privilege and see everything on the host. Restrict who can read their output and secure their update channel like any other agent.
