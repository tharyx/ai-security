# Lab: Inspecting Docker daemon activity

**Course exercise:** "Inspecting Docker Daemon Activity". Lessons: [01 recon, events](../../01-container-reconnaissance.md#8-attack-surface-analysis-with-native-tools); CH12 monitoring (a later chapter).

**Time:** 45 minutes. **Safety:** Event and log fixtures ([events.jsonl](fixtures/events.jsonl), [app.log](fixtures/app.log)). No daemon is queried.

## What it models

Parses `docker events --format '{{json .}}'` lines into a **timeline** and raises **alerts**: privileged or socket-mounting container created, host root mounted, pull from an unapproved registry, exec into a container, out-of-memory kill, crash loop (3 failures), tag moved, daemon reload. Also scans container logs for auth failures, permission probes and encoded payloads.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/inspect-daemon-activity/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/inspect-daemon-activity -v
```

1. Run the demo and match each alert to a fixture line.
2. Add an approved registry and watch `EVT-PULL` change.
3. Add a rule for `container.destroy` of a container created less than 60 seconds ago.
4. Which alert would you page on? Which goes to a daily report?

## Expected output (real run)

```text
Timeline:
  22:13:20 image.pull           registry.example/shop/we
  22:13:30 container.create         shop-web
  22:13:31 container.start          shop-web
  22:15:00 image.pull           evil.example.invalid/too
  22:15:10 container.create         helper
  22:15:20 container.exec_create: sh -c id shop-web
  22:16:40 container.die            worker
  22:17:10 container.die            worker
  22:17:39 container.oom            worker
  22:17:40 container.die            worker
  22:18:20 image.tag            registry.example/shop/we
  22:18:40 daemon.reload         ?

Alerts:
  [CRITICAL] EVT-PRIV       22:15:10  privileged container created: helper (evil.example.invalid/tools/miner:latest)
  [CRITICAL] EVT-SOCK       22:15:10  container helper created with docker.sock mounted
  [HIGH    ] EVT-PULL       22:15:00  image pulled from an unapproved source: evil.example.invalid/tools/miner:latest
  [HIGH    ] EVT-HOSTROOT   22:15:10  container helper mounts the host root
  [MEDIUM  ] EVT-CRASHLOOP  -  worker exited with an error 3 times: crash loop or an attacker probing
  [MEDIUM  ] EVT-EXEC       22:15:20  interactive exec into shop-web: e7f3a9 sh -c id
  [MEDIUM  ] EVT-OOM        22:17:39  worker killed by the out-of-memory killer: possible DoS or leak
  [MEDIUM  ] EVT-DAEMON     22:18:40  daemon configuration reloaded: check daemon.json for changes
  [LOW     ] EVT-TAG        22:18:20  tag moved: registry.example/shop/web:1.0

Log findings:
  line 2: repeated auth failures: 2023-11-14T22:14:02Z WARN  authentication failure for user a
  line 3: repeated auth failures: 2023-11-14T22:14:03Z WARN  authentication failure for user a
  line 4: permission probing: 2023-11-14T22:15:44Z ERROR open /etc/shadow: permission deni
  line 6: encoded payload execution: 2023-11-14T22:17:30Z INFO  exec: echo ZWNobyBoaQ== | base64
```

## Think about it

Events show *what the daemon did*, logs show *what the app said*. You need both, and you need them shipped off the host before an attacker can delete them.

## Run the real tool

`docker events --since 1h --format '{{json .}}'`, `docker logs --since`, `journalctl -u docker`. Falco, Tracee, auditd and Wazuh give richer runtime signals (CH12).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/inspect-daemon-activity`.
