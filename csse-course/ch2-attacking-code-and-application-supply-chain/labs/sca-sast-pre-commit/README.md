# Lab: SCA/SAST using pre-commit hooks

**Course exercise:** "SCA/SAST using pre-commit hooks". Lessons: [08 section 5](../../08-technologies-and-solutions-for-securing-applications.md#5-putting-it-in-the-workflow-pre-commit-and-ci). Builds on: [sca](../sca/README.md), [sast](../sast/README.md), [pre-commit-hooks](../pre-commit-hooks/README.md). Real tools: [real-tools/pre-commit.md](../../real-tools/pre-commit.md), [semgrep-and-bandit.md](../../real-tools/semgrep-and-bandit.md).

**Time:** 30 minutes. **Safety:** no git changes, no installs, no network. Compact scanners and fictional advisories.

## What it does

`pre-commit-config.yaml` is a fixture in the real pre-commit format with two **local** hooks (`sca-check`, `sast-check`). `hookrunner.py` simulates the pre-commit stage:

1. choose the hooks whose `files` pattern matches the **staged** files (others are *Skipped*);
2. run the scanners (`scanners.py`);
3. exit 1 (commit **blocked**) if any hook finds something;
4. unknown `entry` commands **fail closed** (the runner refuses to run an arbitrary command);
5. `--no-verify` is modelled: the commit passes locally, and `ci_recheck` runs the same hooks on the whole tree in CI.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit
```

## Expected output (real run)

```text
== clean change: commit ALLOWED ==
  sca-check    Passed
  sast-check   Passed
== risky code: commit BLOCKED ==
  sca-check    Skipped
  sast-check   Failed
      app.py:2: os.system() call
== vulnerable deps: commit BLOCKED ==
  sca-check    Failed
      requirements.lock: EXAMPLE-2026-0001 [high] examplelib==1.3.0 (fixed in 1.4.2)
      requirements.lock: EXAMPLE-2026-0002 [critical] yaml-lite==0.5.0 (fixed in 0.6.0)
  sast-check   Skipped
== risky code with --no-verify: commit ALLOWED; CI recheck exit code = 1 ==
```

## Break it yourself

1. Hooks that need the network (an SCA lookup against a live database) are slow and flaky at commit time. Which scanner would you move to CI only? (Usually SCA with live data; keep fast, offline SAST and secret scans in the hook.)
2. The config has `repo: local` hooks. Who must review changes to it? (Treat it like CI config: CODEOWNERS.)
3. Make the hook scan only changed lines. What do you gain and lose? (Speed and low noise, but old issues stay hidden: use a baseline plus a full scan in CI.)
