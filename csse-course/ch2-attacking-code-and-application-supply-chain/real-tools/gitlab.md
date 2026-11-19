# GitLab and GitLab CI: hardening and privilege-escalation review

> **Status: hedged outline, not tested by the repo author.** GitLab changes fast. Verify menu names, settings and YAML keys at <https://docs.gitlab.com>. Use a **local throwaway instance** (a container or VM) for practice, never a production one.

**Course exercise:** GitLab privilege escalation. **Offline twin (tested):** [gitlab-privilege-escalation](../labs/gitlab-privilege-escalation/README.md).

## Practice setup (laptop-friendly options)

- GitLab Community Edition in a container needs a lot of RAM (plan for several GB; verify current minimums). On a 16 GB laptop close other apps, or use your course lab.
- Alternatives: a free GitLab.com group used **only with test projects**, or Gitea/Forgejo for the git-hosting concepts.
- Bind to `127.0.0.1` and do not expose it.

## Concepts to check, one per lab finding

| Lab finding | Where to look in GitLab (verify names) | Hardening |
|---|---|---|
| `VAR-UNPROTECTED` | Settings, CI/CD, Variables | mark secrets **Protected** (only protected branches/tags) and **Masked**; scope to an **environment**; prefer **file** type and external secret managers or OIDC |
| `BRANCH-DEV-PUSH` / `DEV-MERGE` | Settings, Repository, Protected branches | allowed to push: **No one** or Maintainers; require merge requests; approvals and code owners |
| `TRIGGER-LOW-ROLE` | Settings, CI/CD, Pipeline trigger tokens | create tokens only when needed, delete unused, never expose in logs |
| `JOBTOKEN-OPEN` | Settings, CI/CD, Job token permissions | restrict job token access with an **allowlist** of projects |
| runners | Settings, CI/CD, Runners | **protected runners** for protected refs; avoid shared runners for sensitive jobs; ephemeral/autoscaled runners; do not run privileged containers (Docker-in-Docker) for untrusted code |
| tokens | project/group access tokens, deploy tokens, personal tokens | least scope, short expiry, rotate |

## A small `.gitlab-ci.yml` to read and lint (concept)

```yaml
stages: [test, build]

test:
  stage: test
  script: [make test]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

build:
  stage: build
  script: [make build]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH     # protected branch only
  # secrets (protected variables) exist only on protected refs
```

Things to check in review: where `include:` pulls templates from, which jobs run on merge requests from forks, which variables each job can see, whether `script` splices untrusted values (`$CI_COMMIT_MESSAGE`, `$CI_COMMIT_REF_NAME` are attacker-influenced; quote and validate), and whether artifacts or caches cross trust levels.

## Review checklist

- [ ] Every secret variable is protected, masked, and scoped.
- [ ] Default branch protected; only reviewed merges.
- [ ] Job token allowlist on; trigger tokens minimal.
- [ ] Runners tagged and protected for protected refs.
- [ ] Group-level inheritance checked (roles inherited from groups can surprise you).
- [ ] Audit events and alerts for new tokens, variables, runners and role changes.
- [ ] Instance patched; open sign-up disabled on self-managed.

## Cleanup

Remove the throwaway instance and any tokens you created.
