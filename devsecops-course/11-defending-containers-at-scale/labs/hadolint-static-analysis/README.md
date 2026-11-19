# Lab: Static analysis of Dockerfiles with Hadolint

**Course exercise:** "Static Analysis using Hadolint" [CCSE 4]. Lesson: [02 section 4](../../02-secure-images-linting-and-scanning.md#4-linting-dockerfiles-hadolint).

**Time:** 30 minutes. **Safety:** nothing is built or run; the linter only reads Dockerfile text.

**Link, do not repeat:** the repo already has a simpler Dockerfile linter in [06-ai-devsecops/docker/lab/dockerfile_lint.py](../../../../06-ai-devsecops/docker/lab/dockerfile_lint.py). This lab adds Hadolint-style rule ids and SARIF output so a pipeline (or the GitLab/GitHub security tab) can ingest the results.

## What it does

[hadolint_lite.py](hadolint_lite.py) lints a Dockerfile and reports findings with Hadolint-**style** ids. The ids below are the ones commonly seen; their exact wording and numbering change between releases, so verify at the source. `DSO-xxx` rules are this lab's own.

| ID | Idea |
|---|---|
| DL3006 / DL3007 | tag the base image; do not use `latest` |
| DL3008 / DL3015 / DL3009 | apt-get: pin versions, `--no-install-recommends`, delete lists |
| DL3002 | last `USER` should not be root |
| DL3003 | use `WORKDIR`, not `cd` |
| DL3020 | use `COPY`, not `ADD` |
| DL3025 | JSON notation for `CMD` / `ENTRYPOINT` |
| DL3042 | `pip install --no-cache-dir` |
| DL4006 | `SHELL ["/bin/bash","-o","pipefail","-c"]` before piped `RUN` |
| DSO-001 to DSO-004 | secret in `ENV`, `curl ... | sh`, `ADD` from URL, no `HEALTHCHECK` |

DBA analogy: this is `sqlfluff` or a code review checklist for DDL, run before anything touches the database.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/hadolint-static-analysis/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/hadolint-static-analysis -v
```

1. Read [Dockerfile.bad](fixtures/Dockerfile.bad) and predict the findings before running.
2. Fix them one at a time until it looks like [Dockerfile.good](fixtures/Dockerfile.good) (0 findings).
3. Look at the SARIF `results[0]`: `ruleId`, `level`, `region.startLine` are what GitHub code scanning reads.
4. Change `gate(fail_on="error")` to `"warning"` and see which pipelines would break.

## Expected output (real run)

```text
== Dockerfile.bad: 12 finding(s); gate(fail_on=error) passes: False
  line  1 DL3006   [warning] Always tag the version of an image explicitly (ubuntu)
  line  1 DSO-004  [info] No HEALTHCHECK (Dockle CIS-DI-0006 style)
  line  2 DSO-001  [error] Secret-looking ENV persists in image layers and `docker history`
  line  3 DL3008   [warning] Pin versions in apt-get install
  line  3 DL3009   [info] Delete the apt-get lists after installing
  line  3 DL3015   [info] Avoid additional packages by --no-install-recommends
  line  4 DL3003   [warning] Use WORKDIR to switch to a directory
  line  4 DL3042   [warning] Avoid cache directory with pip install --no-cache-dir
  line  5 DL3020   [error] Use COPY instead of ADD for files and folders
  line  6 DSO-002  [error] Piping a download into a shell: pin and verify a checksum
  line  8 DL3002   [warning] Last USER should not be root
  line  8 DL3025   [warning] Use arguments JSON notation for CMD
== Dockerfile.good: 0 finding(s); gate(fail_on=error) passes: True
== SARIF: 2.1.0 results = 12
{"ruleId": "DL3006", "level": "warning", "message": {"text": "Always tag the version of an image explicitly (ubuntu)"}, "locations": [{"physicalLocation": {"artifactLo...
```

## Run the real tool (hedged)

```text
hadolint Dockerfile
hadolint --format sarif Dockerfile > hadolint.sarif
hadolint --failure-threshold error Dockerfile
```

Hadolint ships a static binary and a container image. Rules can be ignored with `# hadolint ignore=DL3008` comments or a `.hadolint.yaml`: always add a reason. See [real-tools](../../real-tools/README.md).
