# Lab: Validating a threat model (model versus reality, accounting, tests, "are we done?")

**Course topics:** [CTMP 4] "Validating Threat Models", "Threat Model Versus Reality", "All Threats Accounted For Risk", "Mitigations Are Tested", "Are We Done Threat Modeling?". Lesson: [03 Validating threat models](../../03-validating-threat-models.md).

**Time:** 45 minutes. **Tests:** 7, all offline. **Safety:** fictional JSON inventories and test results. Only test systems you own or have written permission to test.

## Goal

Answer Shostack's fourth question, "Did we do a good enough job?", with checks a machine can run: does the model match what is deployed, does every threat have a decision, is every mitigation proven by a passing test, and are the exit criteria met?

## Concept

[validate.py](validate.py) reads three fixtures:

- [model.json](fixtures/model.json): components, flows, threats with status, mitigation, tests and acceptance;
- [inventory.json](fixtures/inventory.json): what is really deployed (a cloud inventory, Kubernetes services and gateway routes in a real setup) plus flows observed in logs;
- [test_results.json](fixtures/test_results.json): the CI test results.

| Check | Finds |
|---|---|
| `model_vs_reality` | SHADOW components (deployed, not modeled), STALE components (modeled, gone), UNMODELED FLOWS seen in logs |
| `accounted_for` | threats with no decision, mitigated without a mitigation, acceptances without owner/approver/expiry or expired, components and boundary flows with no threats |
| `mitigations_tested` | mitigations with no test, tests that did not run, tests that failed |
| `are_we_done` | five exit criteria, including "model reviewed for the deployed version" and "next review date set" |

The test file builds the **fixed** model (the team's response to every finding) and shows that all exit criteria then pass.

## Steps

```text
.venv/Scripts/python appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-model-validation/demo.py
.venv/Scripts/python -m pytest appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-model-validation -q -p no:cacheprovider
```

1. Run the demo. The `Reports Worker` cron job reads the Orders DB and sends data to a partner SFTP server, and nobody modeled it. This is the most common real-world gap.
2. Read `fixed_inputs()` in the test file: add the worker, remove the stale FTP export, add tests, get an approver, set the next review.
3. Change `test_bola_returns_403` to `fail` in a copy of the results: the BOLA mitigation is "not proven" even though the model says mitigated.

## Expected output (real run of demo.py)

```text
== 1. Threat model versus reality: 4 problems ==
  - SHADOW: Reports Worker is deployed but not in the model
  - STALE: Legacy FTP export is in the model but not deployed
  - UNMODELED FLOW: Reports Worker -> Orders DB seen in VPC flow logs
  - UNMODELED FLOW: Reports Worker -> partner-sftp.example.net seen in egress proxy logs

== 2. All threats accounted for: 4 problems ==
  - T4: accepted without owner, approver and expiry
  - T5: status 'open' is not a decision
  - T6: marked mitigated but no mitigation is described
  - Web App -> Orders API: boundary-crossing flow has no threats

== 3. Mitigations are tested: 3 problems ==
  - T2: test test_bola_returns_403 FAILED, so the mitigation is not proven
  - T3: mitigation 'MFA for admins' has no test
  - T6: mitigation '' has no test

== 4. Are we done threat modeling? ==
  [ ] model matches what is deployed
  [ ] every threat has a decision
  [ ] every mitigation has a passing test
  [ ] model reviewed for the deployed version
  [ ] next review date set
  gate exit code: 1
```

## Run the real tool (hedged)

- **Reality sources:** `aws resourcegroupstaggingapi get-resources`, `az resource list`, `gcloud asset search-all-resources`, `kubectl get svc,ingress -A -o json`, the API gateway's route export, and VPC flow logs or service mesh telemetry. Compare their names with the model in CI (verify CLI options).
- **Test linkage:** tag tests with threat ids (`@pytest.mark.threat("T2")`, Gherkin `@threat-T2`) and publish JUnit XML; parse it like `test_results.json`.
- **Threagile** and commercial platforms track risk status; still compare with the real inventory, because tools only know what you told them.

## What you learned

- Validation compares the model with **reality**, not with itself.
- "Mitigated" means "a passing test proves it"; "accepted" means "owner, approver, expiry".
- You are done for this version when the exit criteria pass, and you are never done for the product: set the next review.
