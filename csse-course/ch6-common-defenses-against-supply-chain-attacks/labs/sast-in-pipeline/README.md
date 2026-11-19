# Lab: Implement SAST as part DevOps pipelines

**Course exercise:** "Implement SAST as part DevOps pipelines". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Semgrep / CodeQL / Bandit in GitLab CI**. Semgrep, CodeQL and Bandit are actively maintained (verify). GitLab's built-in SAST templates change; check the current GitLab docs.

## What the offline twin does

`sast_stage.py` is a pipeline stage built on Python's `ast` module: six rules (eval/exec, `shell=True`, SQL built with `%`, `yaml.load` without a safe loader, md5/sha1, hard-coded credentials), **SARIF-like output**, a **severity gate** and a **baseline** mechanism using line-independent fingerprints so legacy findings do not fail the build but a new one does.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/sast-in-pipeline/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/sast-in-pipeline -v
```

1. Run the demo: vulnerable app fails, fixed app passes.
2. Read the last two lines: legacy code with a baseline passes even after lines shift; a new `exec` fails.
3. Write a seventh rule (for example `pickle.loads`) and a test.

## Expected output (real run)

```text
vulnerable app -> failed
  [high    ] SAST-006 line  3 hard-coded credential
  [high    ] SAST-003 line  6 SQL built with string formatting
  [high    ] SAST-002 line 10 subprocess with shell=True
  [high    ] SAST-004 line 13 yaml.load without a safe loader
  [critical] SAST-001 line 19 eval/exec on dynamic input
  [medium  ] SAST-005 line 16 weak hash (md5/sha1)
fixed app      -> passed
legacy code with baseline -> passed
a NEW eval added          -> failed
```

## Real-tool guide (hedged: verify commands against the current docs)

```yaml
# .gitlab-ci.yml (shape; verify current GitLab docs and Semgrep flags)
sast:
  stage: test
  image: semgrep/semgrep:<pinned>
  script:
    - semgrep scan --config auto --sarif --output semgrep.sarif --error --severity ERROR
  artifacts:
    when: always
    paths: [semgrep.sarif]
# Python only: bandit -r src -f json -o bandit.json
# GitLab Ultimate/CE templates: include: - template: Jobs/SAST.gitlab-ci.yml  (check availability)
```
Repo twins on the same theme: [CAISP ai-code-weaknesses](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md), [CMCPSE sast-vulnerable-mcp-server](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/README.md).
