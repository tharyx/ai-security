# Lab: Malicious container image (and its twin, "Malicious container image" listed again in the syllabus)

**Course exercise:** "Malicious container image". Lessons: [03 section 2](../../03-attacking-the-container-supply-chain.md#2-malicious-images).

**Time:** 45 minutes. **Safety:** the "miner" is a text string (`xmrig-SIMULATED`, a `.example` pool). The inspector reads JSON only and never runs anything. The test `test_inspector_never_executes_anything` guards that.

## What it does

[inspector.py](inspector.py) reads an OCI image config (the same JSON `docker image inspect` shows) and an optional layer file listing, and reports:

| IDs | Checks |
|---|---|
| IMG-001 to IMG-003 | Entrypoint/Cmd pipes a download to a shell, uses encoded or reverse-shell patterns, or contacts unknown hosts |
| IMG-004 to IMG-006 | Runs as root, baked-in secrets, unusual ports |
| IMG-007 to IMG-010 | Build history downloads binaries, mentions mining, installs cron |
| FS-001 to FS-004 | Cron files, hidden binaries, miner strings, planted SSH keys |

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/malicious-image -v
```

1. Run the demo: `clean` is ALLOW, `malicious` is BLOCK with 12 findings.
2. Edit `fixtures/config_malicious.json`: remove the entrypoint download. Which findings disappear? Which remain (history, files)?
3. Add your own internal host suffix to `TRUSTED_HOSTS` and see `IMG-003` change.
4. Evasion thinking: an attacker splits the URL into variables. Which checks still fire? (Hidden binary, cron, ports; so use defence in depth: scanning, egress control, runtime detection.)

## Expected output (real run, abridged)

```text
== clean: ALLOW (0 finding(s)) ==
== malicious: BLOCK (12 finding(s)) ==
  [CRITICAL] IMG-001 Entrypoint/Cmd: downloads a script and pipes it to a shell every time the container starts
  [CRITICAL] FS-003 /usr/bin/.kworker: mining pool or miner string (simulated) in file content
  [HIGH    ] IMG-003 Entrypoint/Cmd: start-up contacts unknown host cdn.updates-miner.example
  ...
```

## Real-tool twin

Trivy (`trivy image`, secrets and misconfiguration scanners), Dive, Syft, `docker history --no-trunc`. See [real-tools/trivy.md](../../real-tools/trivy.md).
