# Lab: Working with docker command

**Course exercise:** "Working with docker command". Lessons: [01](../../01-introduction-to-container-technology.md), [02 native tools](../../02-attack-surface-and-analysis-of-containers.md#5-attack-surface-analysis-with-native-tools).

**Time:** 45 minutes. **Safety:** the simulator only parses text. Docker is not required and no command is executed.

## What you get

- [COMMANDS.md](COMMANDS.md): a security-focused command reference (`run`, `inspect`, `history`, `diff`, `commit`, `save`, `exec`, ...).
- [run_assess.py](run_assess.py): parses `docker run` flags (`--privileged`, `-v`, `--mount`, `--cap-add`, `--network host`, `--pid host`, `--security-opt`, `-e`, `-p`, `--user`, ...) into 18 numbered findings, a risk score and a verdict (OK, WARN, REVIEW, DENY).

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/docker-commands -v
```

1. Run the demo and compare the "sloppy dev", "typical" and "hardened" commands.
2. Try your own: `.venv/Scripts/python run_assess.py "docker run --cap-add SYS_ADMIN alpine"`.
3. Change the hardened command one flag at a time (remove `--read-only`, then `--cap-drop ALL`). Which finding appears?
4. Read [COMMANDS.md](COMMANDS.md) and, if you have Docker, run `docker inspect` on a container and find the same fields (`HostConfig.Privileged`, `Binds`, `CapAdd`).

## Expected output (real run, abridged)

```text
== sloppy dev: DENY (score 53) ==
  [CRITICAL] RUN-001 --privileged: all capabilities, all devices, no seccomp/AppArmor confinement
  [CRITICAL] RUN-002 mounts /var/run/docker.sock: whoever controls it controls the host (can start a privileged container)
  [HIGH    ] RUN-007 --network host: shares the host network stack (reaches localhost services)
  [HIGH    ] RUN-015 secret 'DB_PASSWORD' passed on the command line (visible in docker inspect and shell history)
  ...
== typical: WARN (score 12) ==
== hardened: OK (score 0) ==
```

## Think about it

Why is `-e DB_PASSWORD=...` flagged even though many tutorials do it? (It lands in shell history, `docker inspect` and process listings. Use `--env-file` with tight permissions or a secret store.)
