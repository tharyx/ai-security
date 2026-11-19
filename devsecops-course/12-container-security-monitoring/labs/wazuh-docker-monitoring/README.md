# Lab: Docker security monitoring with Wazuh

**Course topic:** "Docker security monitoring using Wazuh" [CCSE 5]. Lesson: [02 section 3](../../02-runtime-prevention-policy-and-tools.md#3-wazuh-docker-monitoring).

**Time:** 45 minutes. **Safety:** XML rules and JSON events; no Wazuh server.

**Link, do not repeat:** SIEM, alert triage and EDR basics are in [cybersecurity-track 05 SOC](../../../../cybersecurity-track/05-soc-fundamentals/README.md), [06 SIEM](../../../../cybersecurity-track/06-siem-sentinel-splunk/README.md) and [07 EDR/XDR](../../../../cybersecurity-track/07-edr-xdr-mdr/README.md).

## What it does

Wazuh (open-source SIEM/XDR) has a **docker-listener** module (a wodle) in the agent: it subscribes to the Docker daemon's event stream and writes JSON that Wazuh decodes into fields such as `docker.Action`. [wazuh_lite.py](wazuh_lite.py) loads Wazuh-style rules from [local_rules.xml](local_rules.xml):

| Rule | Level | Meaning |
|---|---|---|
| 100201 | 3 | container started (inventory noise: low level) |
| 100202 | 8 | `exec_create: bash` (someone got a shell in a container) |
| 100203 / 100204 | 7 / 8 | exit 137 (killed) / OOM |
| 100205 | 6 | image pulled from outside the approved registry (`negate="yes"`) |
| 100206 | 10 | **frequency** rule: 5 deaths of the same container in 60 s = restart loop |

Levels run 0 to 15. A common pattern: log everything, alert at 7+, page at 12+. The listener module name, option names and event fields are described in the Wazuh docs for your version: verify at source. Custom rule ids live in 100000-119999.

## Steps

```text
.venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/wazuh-docker-monitoring/demo.py
.venv/Scripts/python -m pytest devsecops-course/12-container-security-monitoring/labs/wazuh-docker-monitoring -v
```

1. Run it; then run with `min_level=7`: that is your pager view.
2. Rule 100206 fires once, on the fifth death. Slow the events down (100 s apart): it stops firing. Why does `timeframe` matter?
3. Write a rule for `docker.Action` matching `^kill$` with a `signal` attribute of 9.

## Expected output (real run)

```text
8 rules, 12 events
t=1000 level  3 rule 100201 [c-web] Docker: container started
t=1010 level  8 rule 100202 [c-web] Docker: interactive shell started in a container
t=1020 level  6 rule 100205 [docker.io/evil/miner:latest] Docker: image pulled from a registry that is not the approved one
t=1030 level  8 rule 100204 [c-api] Docker: container hit its memory limit (OOM)
t=1031 level  7 rule 100203 [c-api] Docker: container killed (exit 137: OOM or SIGKILL)
t=1031 level  3 rule 100207 [c-api] Docker: container died
t=1040 level  3 rule 100207 [c-loop] Docker: container died
t=1045 level  3 rule 100207 [c-loop] Docker: container died
t=1050 level  3 rule 100207 [c-loop] Docker: container died
t=1055 level  3 rule 100207 [c-loop] Docker: container died
t=1058 level 10 rule 100206 [c-loop] Docker: container restart loop (5 deaths in 60 s)
t=1058 level  3 rule 100207 [c-loop] Docker: container died
--- only level >= 7 (what you would page on) ---
t=1010 level  8 rule 100202 Docker: interactive shell started in a container
t=1030 level  8 rule 100204 Docker: container hit its memory limit (OOM)
t=1031 level  7 rule 100203 Docker: container killed (exit 137: OOM or SIGKILL)
t=1058 level 10 rule 100206 Docker: container restart loop (5 deaths in 60 s)
```

## Run the real tool (hedged)

See [ossec_docker_listener.conf](ossec_docker_listener.conf): enable the docker-listener wodle in the agent's `ossec.conf`, install the Python `docker` library on the agent host, put rules in `/var/ossec/etc/rules/local_rules.xml`, test with `wazuh-logtest`, restart the manager. Wazuh also runs CIS-style SCA policies and can read the auditd log from [auditd-docker](../auditd-docker/README.md). See [real-tools](../../real-tools/README.md).
