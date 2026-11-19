# Lab: ZAP scan schedules (per commit, weekly, monthly)

**Course exercise:** "using ZAP to configure per commit/weekly/monthly scans". **Lesson:** [02 pipelines, baselines and schedules](../../02-zap-dastardly-pipelines-and-schedules.md). **Real tools:** [Automation Framework](../../real-tools/zap-automation-framework.md), [ZAP Docker scans](../../real-tools/zap-docker-scans.md).

**Time:** 60 minutes. **Tests:** 14, offline. **Safety:** ZAP is **not** run. The lab only writes YAML text, reads JSON report fixtures, and applies rules. Hosts use `.example.test`. Passwords are `${ENV_VAR}` placeholders.

## What it does

[`schedules.py`](schedules.py) has four parts:

1. `generate_plan(profile, target, openapi_url)`: builds a ZAP Automation Framework style plan for **commit** (spider + passive), **weekly** (spider, AJAX spider, active scan, OpenAPI import) or **monthly** (authenticated JSON login, a scan user, a deeper policy, longer budgets). `to_yaml()` writes the YAML.
2. `validate_plan(plan)`: the review checklist as code: allowed target hosts, no active scan in the commit profile, a time budget on every active scan, report job last, passive wait present and before the active scan, known job types, no literal passwords, referenced users and contexts exist, monthly must be authenticated.
3. `parse_zap_report(text)`: reads the `traditional-json` shape (`site[].alerts[]`) from [`fixtures/`](fixtures/).
4. `evaluate_gate(alerts, policy)`: break-build rules per profile with `fail_on`, `max_medium`, `accepted` (documented risk acceptance) and `baseline` (known debt).

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/zap-scan-schedules/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/zap-scan-schedules -v
```

## Expected output (real run, abridged)

```text
== commit: jobs = ['passiveScan-config', 'spider', 'passiveScan-wait', 'report']  validator errors = []
== weekly: jobs = ['openapi', 'passiveScan-config', 'spider', 'spiderAjax', 'passiveScan-wait', 'activeScan', 'report']  validator errors = []
== monthly: jobs = ['openapi', 'passiveScan-config', 'spider', 'spiderAjax', 'passiveScan-wait', 'activeScan', 'report']  validator errors = []

== deliberately bad plan ==
  - context url host 'prod.example.com' is not in the allowed target list
  - passiveScan-wait must come before activeScan
  - commit profile must not run an active scan (too slow, can change data)
  - activeScan has no maxScanDurationInMins: an unbounded scan can hang the pipeline

== break-build gate ==
commit_report.json under 'commit' policy: PASS
weekly_report.json under 'weekly' policy: FAIL
   - High alert 40012 'Cross Site Scripting (Reflected)' (1 instance(s))
   - High alert 40018 'SQL Injection' (1 instance(s))
weekly report with both Highs in the baseline (known debt): PASS
```

## Steps

1. Print the monthly plan (`print(s.to_yaml(s.generate_plan("monthly", T)))`) and find the authentication block and the `${...}` placeholders.
2. Put a literal password into the plan and run the validator.
3. Add a rule to `validate_plan` of your own (for example, every context must exclude `/logout`).
4. Change the weekly policy so Medium alerts above 1 fail the build. Which fixture trips it?
5. Add `accepted={"40018"}` with a comment on who owns the risk and when it expires. Why is a permanent ignore a bad idea?

## Think about it

The commit gate passes the commit fixture even though it has a Medium (CSP header not set). Is that right? (Yes for a baseline gate that fails on High; the monthly policy fails on Medium, so the same finding is fixed on a schedule, not on every commit.)

## Run the real tool

Save `to_yaml()` output to `plan.yaml`, then run it with the Automation Framework as described in [zap-automation-framework.md](../../real-tools/zap-automation-framework.md). Verify job parameter names against your ZAP version first.
