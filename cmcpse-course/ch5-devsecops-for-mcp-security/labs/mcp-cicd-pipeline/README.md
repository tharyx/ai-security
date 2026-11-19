# Lab: A CI/CD Security Pipeline with MCP Checks

**Course exercise:** "Set up a CI/CD security pipeline with automated MCP security checks". Lesson: [05 CI/CD integration and policy as code](../../05-cicd-integration-and-policy-as-code.md).

**Time:** 60 minutes. Offline. Needs `pyyaml` (installed with the repo). The GitHub Actions file is a **fixture under `fixtures/`, not under `.github/`**, so it never runs here. Action SHAs in it are placeholders.

## Files

| File | Role |
|---|---|
| `fixtures/mcp-security.yml` | GitHub Actions workflow: six jobs, `policy-gate` needs all of them, pinned actions, read-only permissions |
| `pipeline_runner.py` | Runs the same stages locally with break-build logic, approvals, and a workflow linter |
| `policy/mcp-policy.yaml` | Policy as code: severity threshold, required stages, approvers, never-waivable codes |
| `fixtures/project-good/`, `fixtures/project-bad/` | A clean MCP project and a compromised pull request (poisoned description, secret, shell exec, vulnerable and unpinned deps, unapproved tool changes) |
| `fixtures/advisories.json` | Fictional local advisories (offline stand-in for pip-audit / OSV) |
| `make_fixtures.py` | Regenerates the fixtures (keeps lock hashes correct) |
| `demo.py`, `test_cmcpse5_pipeline.py` | Demo and 25 tests |

## Stages and finding codes

| Stage | Codes | Reuses |
|---|---|---|
| `sast` | `SAST-MCP001` ... | the scanner from the [SAST lab](../sast-vulnerable-mcp-server/README.md) |
| `secrets` | `SECRET` | `secret_scan.py` from the SAST lab |
| `deps` | `DEP-ADVISORY`, `DEP-UNPINNED`, `DEP-NOLOCK` | idea of [CAISP third-party-vulns](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md) |
| `tool-descriptions` | `DESC-POISON`, `DESC-LONG` | idea of the [tool-security scanner](../../../../04-mcp-security/tool-security/README.md) |
| `manifest-pin` | `PIN-CHANGED`, `PIN-ADDED`, `PIN-REMOVED` | idea of the rug-pull hash pin |
| `policy-gate` | applies `mcp-policy.yaml` | idea of [release_gate and deploy_approval](../../../../06-ai-devsecops/cicd/README.md) |

## Steps

```text
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/demo.py
.venv/Scripts/python cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/pipeline_runner.py --project cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/fixtures/project-bad
.venv/Scripts/python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline -v
```

The runner exits **0** (build may continue) or **1** (build broken): that is what CI uses.

1. Read the workflow fixture and the policy side by side. Which job names does the policy's `required_stages` use?
2. In a copy of `project-good`, change one tool description. Which stage fails? Now set `approved_by` in `pr.json` to `["secops-lead"]`: why does it pass? Put your own name as both author and approver: why does it fail?
3. Add a poisoned phrase to a description and approve it. It still fails: that is `never_waivable`.
4. Edit `policy/mcp-policy.yaml`: add a new required stage and see the gate fail until you implement it.
5. Run `pipeline_runner.lint_workflow` on the fixture, then break it (remove `permissions`, change an action to `@v4`) and see the linter complain.

## Expected output (real run)

```text
===== project-good =====
stage sast               clean     0 finding(s)
stage secrets            clean     0 finding(s)
stage deps               clean     0 finding(s)
stage tool-descriptions  clean     0 finding(s)
stage manifest-pin       clean     0 finding(s)
policy-gate: build may continue (0 blocking)
exit code: 0

===== project-bad =====
stage sast               findings  1 finding(s)
    [high] SAST-MCP001: app.py:8 os.system(...) Shell execution: user text can become a command (MCP05 command injection)
stage secrets            findings  1 finding(s)
    [high] SECRET: server/app.py:4: github-token [FAKE] ghp_...(40 chars)
stage deps               findings  2 finding(s)
    [high] DEP-ADVISORY: yamlish==2.3.0: LAB-ADV-0001 unsafe load allows code execution (fictional lab advisory) (fixed in 2.4.1)
    [high] DEP-UNPINNED: 'requests>=2.0' is not pinned with ==
stage tool-descriptions  findings  3 finding(s)
    [high] DESC-POISON: read_note description: hidden instruction tag
    [high] DESC-POISON: read_note description: concealment from the user
    [high] DESC-POISON: read_note description: sensitive file reference
stage manifest-pin       findings  2 finding(s)
    [high] PIN-CHANGED: tool 'read_note': description or schema differs from the approved lock
    [high] PIN-ADDED: new tool 'send_report' is not in the approved lock
policy-gate: BUILD BROKEN (9 blocking)
exit code: 1

===== workflow fixture lint =====
no problems
```

## Limits

The dependency audit uses a tiny fictional advisory file; in a real pipeline use `pip-audit`/OSV-Scanner/Trivy (the workflow fixture shows a `pip-audit` step). The description scanner is regex-based: it catches obvious poisoning, not clever poisoning. The policy keys `deployment.*` are documentation of intent; the runner does not enforce them (an exercise for you: add a check that rejects `@latest` in a host config file).
