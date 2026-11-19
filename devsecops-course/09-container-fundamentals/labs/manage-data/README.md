# Lab: Manage data in Docker

**Course exercise:** "Manage Data in Docker". Lessons: [03 images, layers and storage](../../03-images-dockerfile-and-registries.md#2-images-and-layers).

**Time:** 45 minutes. **Safety:** A fake host and fake container object in Python. No volumes are created.

## What it models

The three data options (volume, bind mount, tmpfs) plus the container's writable layer: where a write lands and what survives `docker rm`. A risk analyser flags sensitive bind mounts (`/`, `/etc`, `docker.sock`), read-write host mounts and anonymous volumes.

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/manage-data/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/manage-data -v
```

1. Run the demo: which of the four writes survive `docker rm`?
2. Parse your own `-v` strings with `parse_v()` and print `risks()`.
3. Mount `/etc` read-only: is it still a finding? (Yes, HIGH: read-only still leaks `shadow`.)
4. Add `/var/lib/docker` to the sensitive list tests, then try `-v /var/lib/docker:/x`.

## Expected output (real run)

```text
write /var/lib/db/table.dat    -> volume dbdata
write /etc/app/app.conf        -> HOST path /srv/app-config
write /run/secrets/token       -> tmpfs (RAM)
write /tmp/scratch             -> writable layer

After docker rm:
  volume dbdata still has: ['/var/lib/db/table.dat']
  host file changed      : x
  writable layer / tmpfs : {} {}

Risk analysis:
  dbdata:/var/lib/db                             OK
  /var/run/docker.sock:/var/run/docker.sock      CRITICAL: bind mount of /var/run/docker.sock exposes the Docker API (equals root on the host) read-write
  /etc:/host-etc                                 CRITICAL: bind mount of /etc exposes host configuration, passwd, shadow, sudoers read-write
  /srv/app:/app                                  MEDIUM: bind mount /srv/app is read-write: a compromised container can modify host files (use :ro)
  /srv/app:/app:ro                               OK
  /data                                          LOW: anonymous volume at /data: easy to lose track of, hard to back up and clean up
```

## Think about it

Oracle analogy: a volume is a datafile on managed storage, a bind mount is a raw device you handed over, tmpfs is the PGA (gone at shutdown), the writable layer is a scratch tablespace dropped with the instance. Which one would you use for the database files? (A named volume.)

## Run the real tool

`docker volume create`, `docker volume ls`, `docker volume inspect`, `docker run --mount type=bind,src=...,dst=...,readonly`, `docker run --tmpfs /run/secrets`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`7` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/manage-data`.
