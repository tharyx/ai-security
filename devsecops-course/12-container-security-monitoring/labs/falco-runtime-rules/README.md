# Lab: Falco-style runtime protection and monitoring

**Course exercise:** "Sysdig Falco - Runtime Protection and Monitoring" [CCSE 5]. Lesson: [02 section 5](../../02-runtime-prevention-policy-and-tools.md#5-falco-and-tracee).

**Time:** 55 minutes. **Safety:** a pure-Python interpreter over a JSON event file. No kernel hooks.

**Link, do not repeat:** the repo's application-level runtime monitor is [06-ai-devsecops/runtime-security](../../../../06-ai-devsecops/runtime-security/README.md); detection-engineering ideas are in [cybersecurity-track 06 lesson 02](../../../../cybersecurity-track/06-siem-sentinel-splunk/02-detection-engineering.md).

## What it does

[falco_lite.py](falco_lite.py) loads a **subset** of Falco's rule YAML: `list`, `macro`, `rule`; conditions with `and`/`or`/`not`, parentheses, `=`, `!=`, `<`, `>`, `contains`, `startswith`, `endswith`, `in (...)`; fields like `proc.name`, `container.id`, `fd.name`, `evt.type`, `evt.is_open_write`. [rules.yaml](rules.yaml) has four rules:

| Rule | Idea |
|---|---|
| Terminal shell in container | `execve` of `sh`/`bash` with a tty, inside a container |
| Write below etc in container | write-open under `/etc/`, excluding package managers |
| Read sensitive file in container | `/etc/shadow` etc., excluding sshd/sudo/login |
| Outbound connection to a miner port | `connect` to 3333/4444/5555/14444 |

Real Falco (CNCF graduated, from Sysdig) hooks the kernel with a modern eBPF probe (or a kernel module) and has hundreds of fields, `exceptions`, and a default rule set. Field and macro names in the real default rules change between versions: verify at https://falco.org/docs/.

## Steps

```text
.venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/falco-runtime-rules/demo.py
.venv/Scripts/python -m pytest devsecops-course/12-container-security-monitoring/labs/falco-runtime-rules -v
```

1. Run it. Why does the `bash` event on the host (event 2) not alert, nor the `sh -c healthcheck` (event 3)?
2. Why does `apt-get` writing `/etc/apt/sources.list` not alert, while `vi /etc/passwd` does?
3. Write a fifth rule: "package manager run in a running container" (container images should be immutable). Add an event and a test.
4. Tune: which `trusted_readers` would you add for your own base image?

## Expected output (real run)

```text
4 rules, 9 events
event  1 NOTICE   Terminal shell in container: Shell in container (user=root container=web shell=bash cmd=bash)
event  4 ERROR    Write below etc in container: File below /etc opened for writing (user=root proc=vi file=/etc/passwd container=web)
event  6 WARNING  Read sensitive file in container: Sensitive file read (file=/etc/shadow proc=cat container=web)
event  8 CRITICAL Outbound connection to a miner port: Possible miner traffic (proc=xmrig-fake dest=203.0.113.50:3333 container=web)
```

## Run the real tool (hedged)

```text
sudo falco -r rules.yaml            # on a Linux lab host, after installing Falco for your distro
docker run --rm -it --privileged ... falcosecurity/falco   # image and required mounts: follow the current docs
```

Falco needs privileged kernel access (that is the point), so install it on a host or as a DaemonSet in a lab cluster, and send alerts through Falcosidekick to Slack/SIEM. Verify install steps at source. See [real-tools](../../real-tools/README.md).
