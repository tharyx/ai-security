# Lab: Working with pre-commit hooks

**Course exercise:** "Working with pre-commit hooks". Lessons: [02 section 3](../../02-attacks-on-scm-systems.md#3-exploiting-pre-commit-hooks), [08 section 5](../../08-technologies-and-solutions-for-securing-applications.md). Next: [exploiting-pre-commit-hooks](../exploiting-pre-commit-hooks/README.md), [sca-sast-pre-commit](../sca-sast-pre-commit/README.md). Real tool: [real-tools/pre-commit.md](../../real-tools/pre-commit.md).

**Time:** 40 minutes. **Safety:** a temp git repo; built-in checks only; no downloads; the hook runs your own Python.

## What it is

`minipc.py` is a tiny, working clone of the idea behind the `pre-commit` framework (not the real tool). It reads a `.pre-commit-config.yaml`, runs built-in checks on the **staged** files, and exits non-zero when one fails. `install_git_hook()` writes a real `.git/hooks/pre-commit` that calls it, so `git commit` is really blocked.

| Hook id | Catches |
|---|---|
| `trailing-whitespace` | spaces at the end of a line |
| `end-of-file-fixer` | missing final newline |
| `detect-private-key` | files containing a private key header |
| `check-added-large-files` | files over 500 KB |
| `check-merge-conflict` | conflict markers |
| `check-yaml` | invalid YAML |

An unknown hook id **fails closed** (it fails rather than being skipped).

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/pre-commit-hooks/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/pre-commit-hooks
```

## Expected output (real run)

```text
commit with trailing space -> exit 1
trailing-whitespace          Failed
  - a.py:1: trailing whitespace
end-of-file-fixer            Passed
detect-private-key           Passed
check-added-large-files      Passed
check-merge-conflict         Passed
check-yaml                   Passed
after fixing -> exit 0
```

## Break it yourself

1. Run `git commit --no-verify` (the test does). The hook is skipped. What is the lesson? (A client-side hook is a convenience, not an enforcement point: re-run the same checks in CI and with server-side rules.)
2. Delete `.git/hooks/pre-commit`. Hooks live in `.git/` and are **not cloned**, so every developer has to install them. How do you make that reliable? (`pre-commit install` in a setup script; `core.hooksPath` pointing to a reviewed directory; CI as the backstop.)
3. Add a rule that blocks `.env` files. Where would a secret scanner like gitleaks or TruffleHog fit? (As a hook and in CI; see lesson 08.)

## Real life

The real `pre-commit` framework clones each hook repo at a pinned `rev` into a cache and runs its code. Its config is code: read the next lab.
