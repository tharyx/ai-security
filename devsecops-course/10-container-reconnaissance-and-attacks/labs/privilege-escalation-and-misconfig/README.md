# Lab: Privilege escalation methods and security misconfigurations

**Course exercise:** "Privilege escalation methods in Docker; Security misconfigurations". Lessons: [03 privilege escalation and misconfigurations](../../03-container-host-daemon-and-kernel-attacks.md#6-privilege-escalation-methods-in-docker).

**Time:** 45 minutes. **Safety:** Analysis of a host profile fixture. Nothing is executed.

## What it models

Finds **root-equivalent paths** from a host profile: a user in the `docker` group on a rootful daemon, a wrong socket mode, passwordless sudo, a root container with a writable host mount, SetUID binaries without `no-new-privileges`, secrets in env. Shows how **rootless Docker** and **userns-remap** change the severity. Fixtures: [host.json](fixtures/host.json) and [host-rootless.json](fixtures/host-rootless.json).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/privilege-escalation-and-misconfig/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/privilege-escalation-and-misconfig -v
```

1. Run the demo and read the chain for `alice`.
2. Flip `userns_remap` to true: what changes? (CRITICAL becomes HIGH.)
3. Compare with the rootless host: why is the same group membership LOW there?
4. Write the remediation ticket for the CRITICAL rows.

## Expected output (real run)

```text
== host.json ==
  [CRITICAL] alice
      -> alice is in the 'docker' group
      -> group has 660 access to /var/run/docker.sock
      -> the daemon runs as root on the host
      -> a container can be started with the host file system mounted
      -> result: root-equivalent on the host
  [CRITICAL] deploy
      -> deploy is in the 'docker' group
      -> group has 660 access to /var/run/docker.sock
      -> the daemon runs as root on the host
      -> a container can be started with the host file system mounted
      -> result: root-equivalent on the host
  [HIGH    ] deploy
      -> deploy has passwordless sudo for ALL
      -> result: root without any container trick
  [HIGH    ] uploader
      -> uploader runs as root
      -> it has a writable host mount /srv/uploads
      -> files it writes are owned by host root
      -> result: can plant a SetUID file or edit config on the host
  [MEDIUM  ] uploader
      -> uploader image contains SetUID binaries
      -> no-new-privileges is not set
      -> result: easier local privilege escalation inside the container
  [MEDIUM  ] uploader
      -> uploader has secrets in env: DB_PASSWORD
      -> docker inspect (needs docker access) shows them
      -> result: credential theft
  misconfigurations: ['rootful daemon with no user namespace remapping', 'no image signature verification (cosign/Notation) in the pipeline']

== host-rootless.json ==
  [LOW     ] alice
      -> alice uses a ROOTLESS daemon
      -> the daemon and containers run as that same unprivileged user
      -> result: no gain beyond the user's own rights
  misconfigurations: none
```

## Think about it

The `docker` group is not a convenience group: it is `root` with a different name. Treat it like sudo.

## Run the real tool

`id`, `getent group docker`, `ls -l /var/run/docker.sock`, `dockerd-rootless-setuptool.sh install` (hedged), `docker info | grep -i rootless`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/privilege-escalation-and-misconfig`.
