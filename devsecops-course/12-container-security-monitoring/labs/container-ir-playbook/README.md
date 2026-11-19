# Lab: Container incident response playbook

**Course topic:** "Incident response in containers" [CCSE 5]. Lesson: [01 section 3](../../01-monitoring-logs-and-incident-response.md#3-incident-response-in-containers).

**Time:** 45 minutes. **Safety:** a `FakeDocker` class answers from a fixture and records every command. Nothing real is touched. Evidence files go to a `tempfile` directory.

**Link, do not repeat:** the generic IR lifecycle (NIST 800-61: prepare, detect and analyse, contain, eradicate and recover, lessons learned) is in [cybersecurity-track 05 lesson 05](../../../../cybersecurity-track/05-soc-fundamentals/05-incident-response-nist-800-61.md). This lab adds what is **different about containers**.

## What is different about containers

A container is disposable, so the instinct "stop it and redeploy" **destroys the evidence**. The order is:

1. **Preserve** volatile state (inspect, processes, logs, filesystem diff).
2. **Snapshot** (commit, export) for analysis away from production.
3. **Isolate** the network (pause, disconnect) but keep it alive.
4. **Collect** the rest (host connections).
5. **Redeploy clean**: from a rebuilt image with a **different digest**, with rotated secrets.

[runbook.yaml](runbook.yaml) holds the runbook. [ir_playbook.py](ir_playbook.py) executes it against the fake docker and enforces guard rails: a destructive step (`stop`, `rm`) is refused until evidence is preserved and snapshotted **and** the container is detached from every network, and a redeploy is refused if the "clean" image has the same digest as the compromised one. Every evidence file is hashed into `MANIFEST.sha256` (chain of custody).

## Steps

```text
.venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/container-ir-playbook/demo.py
.venv/Scripts/python -m pytest devsecops-course/12-container-security-monitoring/labs/container-ir-playbook -v
```

1. Read the command order in the output. Where does `docker pause` sit, and why before the network disconnect?
2. Delete the `snapshot` phase from the runbook in a test and watch the guard stop the run.
3. Add a step to rotate the secrets the container could read (`inspect.Config.Env`, mounted secrets). Which step order is right? (After isolate, before redeploy: the attacker must not see the new ones.)

## Expected output (real run)

```text
commands in order:
   1. docker inspect c1a2b3c4d5e6
   2. docker top c1a2b3c4d5e6
   3. docker logs --timestamps c1a2b3c4d5e6
   4. docker diff c1a2b3c4d5e6
   5. docker commit --pause c1a2b3c4d5e6 ir/web:ir-2026-0142
   6. docker export c1a2b3c4d5e6
   7. docker pause c1a2b3c4d5e6
   8. docker network disconnect app_net c1a2b3c4d5e6
   9. docker network disconnect bridge c1a2b3c4d5e6
  10. ss -tnp
  11. docker stop c1a2b3c4d5e6
  12. docker rm c1a2b3c4d5e6
  13. docker run -d --name web registry.example.invalid/shop/web:2.1
evidence manifest (sha256):
  b08216f1aab867c8...  commit.id
  544072bd542d4ff5...  container.log
  54226723adbc99d1...  filesystem.diff
  e97a9a58ed711ce2...  host-connections.txt
  ce8a19974b824bfa...  inspect.json
  47f44a9354c22c74...  processes.txt
  60e86361db11f713...  rootfs.tar
network list after isolate: [] | paused: True
--- guard: redeploying the same image digest is refused ---
refused: refusing to redeploy the compromised image digest
```

## Run the real tool (hedged)

The commands in the runbook are real Docker CLI commands. Notes: `docker commit` includes the container's writable layer, not memory; for memory capture use a host-level tool, or checkpoint/restore (CRIU) where supported (experimental, verify). In Kubernetes use `kubectl debug`, network policies for isolation and node cordoning. Decide in advance who may run this and where evidence is stored.
