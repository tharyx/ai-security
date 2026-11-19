# Lab: Creating container snapshots

**Course exercise:** "Creating container snapshots". Lessons: [01 section 3](../../01-introduction-to-container-technology.md#3-basics-of-container), [02 section 5](../../02-attack-surface-and-analysis-of-containers.md#5-attack-surface-analysis-with-native-tools).

**Time:** 45 minutes. **Safety:** images are built in memory from JSON; the canary strings are harmless. Nothing is extracted to disk.

## Concepts

- `docker commit` turns the container's writable layer into a **new layer** on top of the image.
- `docker save` writes a tar: `manifest.json`, a config JSON, and one tar per layer.
- `docker diff <container>` lists added, changed and deleted paths.
- Snapshots help **forensics** (what did the intruder change?) and **rollback**, but they also freeze whatever the intruder planted. Never push a committed container image without diffing it.

## Files

- [snapshot.py](snapshot.py): `commit`, `save` (real tar with `manifest.json`), `load`, `flatten`, `diff`, `suspicious`.
- [fixtures/base_layers.json](fixtures/base_layers.json), [fixtures/container_changes.json](fixtures/container_changes.json).

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/container-snapshots/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/container-snapshots -v
```

1. Read the demo output: lower layer digests do not change; the commit adds one layer.
2. Add another file to `container_changes.json` under `/etc/profile.d/` and confirm `suspicious` flags it.
3. Read `test_deleted_secret_still_exists_in_lower_layer`: a file deleted in a later layer is invisible in the running container but still inside the image tar.

## Expected output (real run)

```text
== v2 layers (after docker commit) ==
layer 0 sha256:bfdb3398e954... 3 file(s) (ADD rootfs.tar /)
layer 1 sha256:8a2242614df4... 2 file(s) (COPY app/ /srv/app/)
layer 2 sha256:4395c0e53ab4... 5 file(s) (docker commit shop-container)
added: ['/etc/cron.d/refresh', '/srv/app/notes.txt', '/usr/local/bin/healthcheck.sh']
modified: ['/srv/app/config.yaml']
removed: ['/etc/passwd']
suspicious additions: ['/etc/cron.d/refresh', '/usr/local/bin/healthcheck.sh']
first two layer digests unchanged: True
```

## Real-tool twin

`docker commit`, `docker save -o x.tar`, then `tar tf x.tar`; `dive`; `container-diff` or `skopeo`. See [real-tools/docker.md](../../real-tools/docker.md).
