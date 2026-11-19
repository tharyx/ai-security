# Lab: Design a web-app pipeline and simulate blue/green

**Lesson:** [02 sections 5 to 7](../../02-cicd-and-deployment-strategies.md#5-blue-green-deployment-and-its-cousins) · **Time:** 1.5 hours · **Safety:** offline; nothing is deployed, `pipeline.py` only reads YAML and simulates a router.

## Part 1: the design validator

`pipeline.yaml` describes the pipeline of a web shop: stage `type`, whether it is `blocking`, a `fail_on` threshold, and for production a `strategy`, `approval`, `health_check` and `rollback`. `validate(spec)` checks:

| Rule | Meaning |
|---|---|
| `missing-gate` | Each required type exists: secrets-scan, sca, sast, build, image-scan, dast, deploy-staging, deploy-prod |
| `order` | Secrets, SAST and SCA before build; image scan after build and before any deploy; DAST after staging and before prod; sign before prod |
| `not-blocking` | Security gates must block (no `allow_failure`) |
| `no-threshold` (warning) | A gate without `fail_on` has no clear pass or fail line |
| `strategy`, `rollback`, `health-check` | Production needs a safe strategy, automatic rollback and a health check |
| `approval` | In `mode: delivery` a manual approval is required |
| `missing-sign`, `branch` (warnings) | Unsigned images; production from a branch other than `main` |

It is a **design** file, not a runnable CI file. The same design turned into real syntax for five CI systems is in [chapter 2](../../../02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform/README.md).

## Part 2: blue/green and canary simulators

`BlueGreen.release(version, health, post_flip, retries)`:

1. Deploy to the **idle** environment.
2. Run the health check (with retries). If it never passes, **abort**: users never left the live environment.
3. **Flip** the router.
4. Run the post-flip check (think error rate). If it fails, **roll back** by flipping the router back.
5. Otherwise keep the old environment warm for a fast manual `rollback()`.

`canary_rollout(steps, error_rate_for, max_error)` raises traffic in steps (5, 25, 50, 100 percent) and stops and rolls back at the first step whose error rate is too high.

## Steps

```text
.venv/Scripts/python devsecops-course/01-devops-devsecops-and-maturity/labs/pipeline-design/demo.py
.venv/Scripts/python -m pytest devsecops-course/01-devops-devsecops-and-maturity/labs/pipeline-design -v
```

1. Validate the sample. It should be clean. Now set `allow_failure: true` on `sca` and re-validate.
2. Move `sast` below `build`. Which message do you get?
3. Switch `mode` to `deployment`. Is the manual approval still required? Which risk does this create?
4. Change the strategy to `canary` and run the canary simulator with an error curve of your choice.
5. Make the health check fail twice and then succeed. Does the release go through? (Yes: retries tolerate warm-up.)
6. Stretch: add a rule that `deploy-prod` must run only after `sign` and print the exact rule that fired.

## Expected output (real run)

```text
== validate pipeline.yaml
  issues: none
== validate a broken copy (no DAST, SCA may fail, no rollback)
  error    missing-gate   required stage type 'dast' is missing
  error    not-blocking   gate 'sca' must be blocking
  error    rollback       deploy-prod needs rollback: automatic

== blue/green: good release
   deploy 1.1.0 to idle env 'green' (live is still 'blue')
   health check 1/3 on 'green': ok
   flip router: live is now 'green' (1.1.0)
   post-flip check ok; keep 'blue' warm for fast rollback

== blue/green: health check never passes
   deploy 1.1.0 to idle env 'green' (live is still 'blue')
   health check 1/3 on 'green': FAIL
   health check 2/3 on 'green': FAIL
   health check 3/3 on 'green': FAIL
   abort: users never left 'blue'
  status: aborted | live: blue

== blue/green: healthy, but errors after the flip
   deploy 1.1.0 to idle env 'green' (live is still 'blue')
   health check 1/3 on 'green': ok
   flip router: live is now 'green' (1.1.0)
   post-flip check FAILED: rollback, router back to 'blue'
  status: rolled-back | live: blue

== canary: 5% 25% 50% 100%, errors jump at 50%
   {'status': 'rolled-back', 'stopped_at': 50, 'history': [(5, 0.002), (25, 0.002), (50, 0.05)]}
```

## Limits

A router flip here is a variable. Real blue/green also needs shared database compatibility (expand then contract), session handling, cache warming and DNS or load-balancer behaviour. Real validators for CI files are in [chapter 2](../../../02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform/README.md).
