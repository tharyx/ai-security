# Lab: Working with GitLab CI/CD and understanding stages

**Course exercises:** "Working with Gitlab CI/CD" and "Understanding Stages in CI/CD Pipelines". Lesson: [05 sections 2.3 and 2.4](../../05-cicd-stages-and-deployment.md#23-working-with-gitlab-cicd). Real tool: [GitLab quickstart](../../real-tools/gitlab-ci-quickstart.md).
**Time:** 40 minutes. **Safety:** static YAML analysis only. The token in the starter file is FAKE.

## What you do

Edit [starter.gitlab-ci.yml](starter.gitlab-ci.yml) until `stage_checker.py` shows four PASS lines.

| Exercise | Goal | Why |
|---|---|---|
| EX1 | Add a `test` stage between `build` and `deploy`, with a job in it | Nothing should deploy untested |
| EX2 | Add a `security` stage before `deploy` with scan jobs (names such as `sast`, `secret-scan`) | A scan after deploy is too late |
| EX3 | Make the production deploy run only on `main` and only manually (`rules` with `when: manual`) | A protected, human gate |
| EX4 | Remove the secret-looking value from `variables:` | Secrets belong in masked, protected CI/CD variables |

```text
.venv/Scripts/python csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/stage_checker.py csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/starter.gitlab-ci.yml
.venv/Scripts/python -m pytest csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages -v
```


Compare with [solutions/solution.gitlab-ci.yml](solutions/solution.gitlab-ci.yml) **after** you try.

## Think about it

1. Why is `when: manual` at job level not enough for EX3? (It does not limit the branch; a feature branch could reach the gate.)
2. What changes if a security job has `allow_failure: true`? (It becomes advice, not a gate.)
3. Run your edited file through the [pipeline runner](../how-cicd-works/README.md) to see the execution order.
4. Stretch: add a container-scan job and make the manual deploy `needs` it.

## Expected output (real run of `demo.py`)

```text
== starter (your exercise file)
  FAIL  EX1  no 'test' stage in stages:
  FAIL  EX2  no security stage (security, scan or sast)
  FAIL  EX3  prod deploy must have a rule: if $CI_COMMIT_BRANCH == "main" with when: manual
  FAIL  EX4  secret-looking values in YAML: DEPLOY_TOKEN (use masked, protected CI/CD variables)
  columns: {'build': ['build-app'], 'deploy': ['deploy-prod']}
== reference solution
  PASS  EX1  test stage exists, in order, with a job
  PASS  EX2  security stage before deploy with scan job(s): secret-scan, sast
  PASS  EX3  prod deploy is manual and limited to main
  PASS  EX4  no secret values in the YAML
  columns: {'build': ['build-app'], 'test': ['unit-tests'], 'security': ['secret-scan', 'sast'], 'deploy': ['deploy-prod']}
```
