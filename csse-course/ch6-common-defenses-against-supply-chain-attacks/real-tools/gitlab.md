# GitLab CI for supply chain controls (hedged)

> Verify syntax against the GitLab documentation for your version (GitLab.com and self-managed differ in features and tiers).

## Concepts to know

| Concept | Why it matters for supply chain security |
|---|---|
| **Stages and jobs** | `stages:` define order; a job has `stage`, `script`, `rules`, `artifacts`, `needs`. |
| **`rules:`** | decide when a job runs (branch, tag, merge request). Replace the older `only/except`. |
| **Runners** | run the jobs. Shared vs project runners, Docker vs shell executor. A job on a shared runner with the shell executor can see more than you expect. Prefer ephemeral, isolated runners ([lesson 05](../05-code-isolation-and-sandboxing.md)). |
| **Protected branches and tags** | control who can push and merge; limit release tagging. |
| **Protected and masked variables** | protected variables are exposed only to pipelines on protected branches and tags; masked variables are hidden in logs (masking is not a perfect protection). |
| **Job tokens (`CI_JOB_TOKEN`)** | short-lived; restrict which projects it can reach. |
| **Project/group access tokens** | give narrow scopes and short expiry; review regularly. |
| **Merge request approvals, CODEOWNERS, push rules** | [lesson 03](../03-change-control-and-licensed-code.md). |
| **Privilege escalation concepts (conceptual)** | over-broad roles (Maintainer/Owner), runner registration tokens exposed in variables or logs, pipelines editable from untrusted merge requests, and variables exposed to unprotected branches. See chapter 2. |
| **Pipelines for merge requests from forks** | do not expose secrets to them. |

## A minimal supply-chain pipeline (shape)

```yaml
stages: [pre, build, test, package]

secrets:
  stage: pre
  image: <trufflehog image pinned by digest>
  script: [trufflehog git file://. --since-commit "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --only-verified --fail]
  rules: [{if: '$CI_PIPELINE_SOURCE == "merge_request_event"'}]

sca:
  stage: test
  image: <trivy image pinned by digest>
  script: [trivy fs --scanners vuln,license --severity HIGH,CRITICAL --exit-code 1 .]

sbom:
  stage: package
  image: {name: <syft image pinned>, entrypoint: [""]}
  script: [syft dir:. -o cyclonedx-json=sbom.cdx.json]
  artifacts: {paths: [sbom.cdx.json], expire_in: 90 days}
  rules: [{if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_COMMIT_TAG'}]
```

GitLab also offers built-in security templates and a dependency list / security dashboard in some tiers (check availability), and its own container registry and package registry.

## Offline practice

[syft-in-cicd](../labs/syft-in-cicd/README.md) runs a mini pipeline runner from a `.gitlab-ci.yml` fixture; no GitLab is needed.

## Housekeeping

- Keep `.gitlab-ci.yml` under CODEOWNERS.
- Use `include:` from a **protected, versioned** central repository for shared templates, referencing a tag or commit, not a moving branch.
- Review which variables are protected and who can read them.
