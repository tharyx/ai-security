# Lesson 03: Validating Threat Models ("Did We Do a Good Enough Job?")

**Syllabus items covered:** [CTMP 4] "Validating Threat Models", "Threat Model Versus Reality", "All Threats Accounted For Risk", "Mitigations Are Tested", "Are We Done Threat Modeling?".

**Time:** 1 hour plus lab. **Safety:** fictional systems.

> **DBA analogy.** You never trusted a backup until you restored it. You should not trust a threat model until you have checked it against the running system and proved its mitigations with tests. Validation is the restore test of threat modeling.

## 1. What validation means

Validation answers the fourth question of the Threat Modeling Manifesto: **did we do a good enough job?** Four checks (after Shostack):

| Check | Question |
|---|---|
| **Model versus reality** | Does the model describe what is actually built and deployed? |
| **All threats accounted for** | Does every threat have a decision (mitigate, accept, transfer, avoid) with an owner? |
| **Mitigations are tested** | Does a test prove each mitigation works? |
| **Are we done?** | Are the exit criteria for this version met, and when is the next review? |

## 2. Threat model versus reality

Models drift: a cron job is added, a debug endpoint ships, a "temporary" SFTP export becomes permanent. Compare the model with sources of truth:

- **Inventory:** cloud resource inventories, Kubernetes services and ingresses, API gateway routes, OpenAPI specs, CMDB.
- **Observed traffic:** VPC flow logs, service mesh telemetry, egress proxy logs, load balancer logs.
- **Code:** new dependencies, new outbound calls, new secrets.
- **People:** walk the diagram with the engineers who run the system; ask "what is missing?"

Findings are **shadow** components (deployed, not modeled), **stale** components (modeled, gone) and **unmodeled flows**. Each one is either a model update or a removal ticket. The [validation lab](labs/threat-model-validation/README.md) automates this comparison.

## 3. All threats accounted for

Every threat ends in exactly one decision:

| Decision | Valid when |
|---|---|
| **Mitigate** | A mitigation is described, implemented and tested |
| **Accept** | Owner, approver at the right authority level, reason, expiry date |
| **Transfer** | To whom (provider, insurer, partner) and evidence (contract clause) |
| **Avoid** | The feature or flow was removed |
| **Not applicable** | A reason (and it is not a disguised acceptance) |

Also check **coverage**: every component and every boundary-crossing flow has been analysed (at least one threat considered or an explicit "no threats, because..."). Chapter 03 covers the four risk treatments in depth.

## 4. Mitigations are tested

"Mitigated" in a model is a claim. Turn it into evidence:

- Link each mitigation to a test id: unit test, BDD abuse-case scenario, DAST rule, infrastructure policy test.
- The test must **run** in CI and **pass**. A failing or missing test means "not proven".
- Prefer tests that perform the attack (BOLA returns 403) over tests that only check configuration exists.
- Re-test after refactors; penetration tests and bug bounty findings validate the model from the outside.

## 5. Are we done threat modeling?

For **a version** you are done when the exit criteria pass, for example:

- [ ] the model matches what is deployed (no shadow, stale or unmodeled items);
- [ ] every threat has a valid decision;
- [ ] every mitigation has a passing test;
- [ ] the model was reviewed for this release version;
- [ ] a next review date is set (and triggers are defined).

For **the product** you are never done: re-model on change triggers (new interface, data type, trust boundary, third party, authentication change), after incidents, and at least yearly. Diminishing returns are a good stop signal for a session: when a new pass finds only low, already-covered threats, stop.

## 6. Scenario: the reports worker

A shop's threat model was "complete" and green in CI. During validation the team compared it with the Kubernetes inventory and VPC flow logs and found a `reports-worker` cron job that read the whole Orders DB with the application's admin account and pushed a CSV to a partner SFTP server every night. Nobody had added it to the model because it was "just a script". It became two threats (excessive DB privilege, data disclosure to a third party), a read-only role, a contract clause (transfer) and a test that the worker's role cannot write.

## 7. Common mistakes

- Validating the model against itself (only consistency checks).
- "Mitigated" with no test.
- Acceptances without approver or expiry.
- No next review date.
- Treating a pen test as the validation; it is one input.

## 8. Checklist

- [ ] I can name the four validation checks.
- [ ] I can list three sources of truth for model versus reality.
- [ ] I can say what makes an acceptance valid.
- [ ] I can write exit criteria for "done for this version".

## References

- Adam Shostack, *Threat Modeling: Designing for Security*, chapter on validating threat models.
- Threat Modeling Manifesto; OWASP Threat Modeling Cheat Sheet.
- Repo: [chapter 03 risk treatments](../03-risk-management-and-threat-modeling-overview/), [devsecops-course BDD security lab](../../devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/README.md).
