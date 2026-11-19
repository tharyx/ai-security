# Lab: Writing Dockerfile

**Course exercise:** "Writing Dockerfile". Lessons: [03 Dockerfile best practices](../../03-images-dockerfile-and-registries.md#4-writing-a-good-dockerfile).

**Time:** 45 minutes. **Safety:** A linter over text. It reuses the parser from [dockerfile-build](../dockerfile-build/README.md).

## What it models

A small best-practice **linter** (11 rules: unpinned base, secret in `ENV`, `ADD` from a URL, `curl | sh`, root user, no healthcheck, bad cache order and more) and a **rebuild cost** comparison between a bad and a good Dockerfile. Fixtures: [bad.Dockerfile](fixtures/bad.Dockerfile), [good.Dockerfile](fixtures/good.Dockerfile). The fuller repo linter is the [06 Docker lab](../../../../06-ai-devsecops/docker/README.md); the real tool is Hadolint.

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/writing-dockerfile/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/writing-dockerfile -v
```

1. Run the demo, then fix `bad.Dockerfile` finding by finding until the score is 0.
2. Check the rebuild cost after each fix: which fix saved the most rebuild time?
3. Write your own Dockerfile for a small app and lint it.
4. Compare the findings with `hadolint` if you have it.

## Expected output (real run)

```text
== bad.Dockerfile: 9 findings, score 32 ==
  [CRITICAL] DF-003 line  2: secret in ENV: it stays in the image config and history for everyone who pulls
  [HIGH    ] DF-001 line  0: base image python:latest is not pinned (latest): builds are not reproducible
  [HIGH    ] DF-005 line  6: curl | sh: executes whatever the server returns at build time
  [HIGH    ] DF-009 line  0: final stage runs as root: add a non-root USER
  [MEDIUM  ] DF-004 line  3: ADD from a URL: unverified download; use COPY plus a checksum-verified RUN
  [LOW     ] DF-006 line  5: apt-get install without --no-install-recommends: larger image, more CVEs
  [LOW     ] DF-008 line  9: shell-form CMD: runs under /bin/sh -c and does not receive signals; use exec form
  [LOW     ] DF-010 line  0: no HEALTHCHECK: the orchestrator cannot tell a hung container from a healthy one
  [LOW     ] DF-011 line  7: dependencies installed after COPY . : every source edit re-installs them; copy the m
  edit app.py -> rebuilt 4 of 5 layers (120123 KB)

== good.Dockerfile: 0 findings, score 0 ==
  edit app.py -> rebuilt 2 of 4 layers (121 KB)
```

## Think about it

Why is the digest pin `@sha256:...` a security control and the tag `3.12-slim` only a convenience? (A tag can be moved by the publisher or an attacker; a digest cannot.)

## Run the real tool

`hadolint Dockerfile`, `docker build --no-cache`, `dockle IMAGE` (image linter). See [real-tools/docker.md](../../real-tools/docker.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`7` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/writing-dockerfile`.
