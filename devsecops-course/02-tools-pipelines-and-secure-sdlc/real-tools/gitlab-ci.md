# GitLab CI: running and hardening the secure pipeline (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** Verify keywords at <https://docs.gitlab.com/ee/ci/yaml/>. Repo tests never need GitLab.

**Offline twin (tested):** [ci-pipeline-multi-platform](../labs/ci-pipeline-multi-platform/README.md) validates [fixtures/gitlab-ci.yml](../labs/ci-pipeline-multi-platform/fixtures/gitlab-ci.yml). Basics: [chapter 1 guide](../../01-devops-devsecops-and-maturity/real-tools/gitlab-ci.md) and [csse ch1 quickstart](../../../csse-course/ch1-introduction-to-supply-chain-security/real-tools/gitlab-ci-quickstart.md).

## Run the fixture

1. Create a project with a small Node app (or any app; adapt the `sca` and `build` jobs).
2. Copy the fixture to `.gitlab-ci.yml`. Replace `registry`, `deploy.sh` and the image tags with ones you have verified.
3. Make sure the project has a runner that can run Docker-executor jobs. Kaniko builds do not need privileged mode.
4. Open a merge request. Watch the stages: secrets, sca, sast, build, image-scan, dast, deploy.

## Hardening checklist

| Item | Where | Why |
|---|---|---|
| Protected default branch, merge request approvals | Settings, Repository | Nobody pushes straight to production code |
| Require pipelines to succeed before merge | Settings, Merge requests | Gates become real |
| Variables **masked** and **protected** | Settings, CI/CD, Variables | Protected variables are only passed to protected branches and tags |
| CODEOWNERS on `.gitlab-ci.yml` | Repository file | Pipeline changes get a security review |
| Pin images by tag or digest | `.gitlab-ci.yml` | Scanner and base images are code you run |
| `id_tokens` (OIDC) for cloud deploys | `deploy` job | No long-lived cloud keys in variables |
| Deploy only from the default branch | `rules:` | Feature branches cannot deploy |
| Avoid personal access tokens in jobs | n/a | Use the job token or OIDC; PATs outlive their purpose |
| Central CI templates (`include:`) | A shared project | Teams cannot silently drop security jobs |

## Notes

- GitLab provides ready-made templates for SAST, dependency scanning, secret detection, container scanning and DAST. **Which are free and which need a paid tier changes**: check the current docs before planning around them.
- Findings from GitLab's own scanners and from your own jobs can both be uploaded as reports. For your own tools, produce SARIF or the tool's JSON and normalise it ([findings lab](../labs/manage-findings-automatically/README.md)).
