# The `pre-commit` framework: use it safely

> **Status: hedged outline, not tested by the repo author.** Verify at <https://pre-commit.com>. Hook repositories and versions below are examples.

**Offline twins (tested):** [pre-commit-hooks](../labs/pre-commit-hooks/README.md) (working hooks), [exploiting-pre-commit-hooks](../labs/exploiting-pre-commit-hooks/README.md) (why config is code), [sca-sast-pre-commit](../labs/sca-sast-pre-commit/README.md).

## Install and use (outline)

```text
python -m venv .venv && .venv/Scripts/activate      # Windows; use bin/activate elsewhere
pip install pre-commit                              # pin the version in your own tooling
pre-commit --version
# in a repo YOU have reviewed:
pre-commit install            # writes .git/hooks/pre-commit
pre-commit run --all-files    # the same checks as CI
```

Hooks are fetched from the repositories named in `.pre-commit-config.yaml` at the pinned `rev` and cached on your machine, then they run **as you**.

## A reviewed config (example shape)

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: <full commit SHA or version tag>      # pin; `pre-commit autoupdate` can update (see --freeze for SHAs)
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
  - repo: https://github.com/gitleaks/gitleaks      # secret scanning (verify the current hook id and rev)
    rev: <pinned>
    hooks:
      - id: gitleaks
  - repo: https://github.com/PyCQA/bandit            # Python SAST (verify)
    rev: <pinned>
    hooks:
      - id: bandit
```

Verify each hook's id and the recommended `rev` in that project's README. `pre-commit autoupdate --freeze` (verify the flag) replaces tags with commit SHAs.

## Safety rules (from the exploiting lab)

1. **Never run `pre-commit install` or `pre-commit run` in a repo you have not reviewed.** Read the config and any `repo: local` hook scripts first.
2. **Pin revs** to a tag, better a SHA; do not use branch names.
3. **Allowlist hook repositories** (a CI check can reject unknown ones).
4. **CODEOWNERS** on `.pre-commit-config.yaml` and `.githooks/`.
5. **Run pre-commit in CI** (`pre-commit run --all-files`) because `git commit --no-verify` skips local hooks. The pre-commit project also offers a hosted CI service (verify).
6. Keep hooks fast and offline when possible.

## Cleanup

`pre-commit uninstall`, and delete the cache directory (see `pre-commit clean`).
