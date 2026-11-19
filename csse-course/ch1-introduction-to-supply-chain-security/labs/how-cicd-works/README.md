# Lab: How CI/CD Works (a tiny pipeline runner)

**Course exercise:** "How CI/CD Works". Lesson: [05 section 2.2](../../05-cicd-stages-and-deployment.md#22-how-cicd-works). Real tool: [GitLab quickstart](../../real-tools/gitlab-ci-quickstart.md).
**Time:** 45 minutes. **Safety:** nothing is executed. `script` lines are simulated: `echo`, `write`, `require`, `exit`, `call` (a Python callable you pass in); anything else is only recorded as `(simulated) ...`.

## What it models

| GitLab idea | In `pipeline.py` |
|---|---|
| `stages` order | Jobs of a stage start only after every active job of earlier stages is done |
| Parallel jobs in a stage | They share a "round" number |
| Failure | A failed job fails the pipeline; later stages are `skipped`; same-stage siblings still run |
| `allow_failure: true` | Status `failed_allowed`; the pipeline continues |
| `needs` | The job waits only for named jobs and gets only their artifacts |
| `rules: - if:` | `$VAR`, `$VAR == "x"`, `!=`, `&&`, `||`; first match wins; no match means the job is `excluded` |
| `when: manual` | Status `manual`; the pipeline is `blocked` until you pass the job in `approved` |
| `artifacts: paths:` | Only listed files survive; only successful jobs pass artifacts on |
| Validation | Unknown stage, missing script, unknown `needs`, `needs` on a later stage, cycles |

## Steps

```text
.venv/Scripts/python csse-course/ch1-introduction-to-supply-chain-security/labs/how-cicd-works/demo.py
.venv/Scripts/python -m pytest csse-course/ch1-introduction-to-supply-chain-security/labs/how-cicd-works -v
```

1. Read [sample.gitlab-ci.yml](sample.gitlab-ci.yml). Predict the order of jobs on `main` and on a feature branch, then run the demo.
2. Rename the artifact path in `compile`. Which job fails and why? (A file that is not listed in `artifacts:` is lost.)
3. Add `needs: [compile]` to `deploy-prod`. In which round does it run now? Why is that dangerous if `unit-tests` was your gate? (It no longer waits for the test stage. Add `unit-tests` to `needs`.)
4. Make `lint` blocking (remove `allow_failure`). What happens to `deploy-prod`?
5. Add `when: manual` to `deploy-prod` and call `run_pipeline(..., approved={"deploy-prod"})` in a Python shell.
6. Stretch: add `retry` support, or `artifacts: when: always`.

## Expected output (real run)

```text
== on a feature branch: pipeline SUCCESS
  deploy-prod  deploy  excluded        -        rules did not match
  compile      build   success         round 1  
  unit-tests   test    success         round 2  
  lint         test    failed_allowed  round 2  failure allowed
  order: compile -> unit-tests -> lint

== on main: pipeline SUCCESS
  compile      build   success         round 1  
  unit-tests   test    success         round 2  
  lint         test    failed_allowed  round 2  failure allowed
  deploy-prod  deploy  success         round 3  
  order: compile -> unit-tests -> lint -> deploy-prod

== main, but compile forgot its artifact: pipeline FAILED
  compile      build   success         round 1  
  unit-tests   test    failed          round 2  
  lint         test    failed_allowed  round 2  failure allowed
  deploy-prod  deploy  skipped         round 3  dependency not successful: unit-tests
  order: compile -> unit-tests -> lint

== deploy-prod with needs: [compile]: pipeline SUCCESS
  compile      build   success         round 1  
  unit-tests   test    success         round 2  
  lint         test    failed_allowed  round 2  failure allowed
  deploy-prod  deploy  success         round 2  
  order: compile -> unit-tests -> lint -> deploy-prod
```

## Limits (it is a teaching model)

No `include`, `extends`, `parallel`, `trigger`, `retry`, services, caches or real runners. Real GitLab makes `when: manual` non-blocking by default outside `rules`; this model treats it as blocking unless `allow_failure: true`. Check the GitLab docs.
