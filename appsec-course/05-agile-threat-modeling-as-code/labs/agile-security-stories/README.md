# Lab: Security user stories, abuse cases and Scrum events as code

**Course exercises:** [CTMP 3] "Writing Security Requirements for Agile Software Development", "Writing Use Cases and Abuse Cases", "Events of Agile Software Development Through Scrum", "Security Requirements as Code With BDD Security". Lessons: [01 Agile threat modeling and Scrum](../../01-agile-threat-modeling-and-scrum.md), [03 Security requirements, user stories and abuse cases](../../03-security-requirements-user-stories-and-abuse-cases.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** JSON backlog fixtures only. Only test systems you own or have written permission to test.

## Goal

Treat the product backlog as data and check it like code: every security-relevant story needs an abuse case (Definition of Ready) and a `SEC:` acceptance criterion; every abuse case needs an attacker's point of view, a mitigating story and a testable Given/When/Then; security-relevant stories must be threat modeled at **Sprint Planning**; and a story is not **done** until its security tests pass. Then turn the abuse cases into Gherkin scenarios.

## Concept

[agile_sec.py](agile_sec.py):

- `parse_story()` checks the "As a <role>, I want <goal> so that <benefit>" form.
- `is_security_relevant()` flags stories by tag (`auth`, `pii`, `payment`, `admin`, `upload`, `export`, `secrets`) or by words (login, password, reset, card, upload, admin, export, personal, token).
- `check_backlog()` returns the problems; `gate()` returns 1 if there are any.
- `to_gherkin()` writes one tagged scenario per abuse case (`@threat-AB-2 @information-disclosure`).
- `SCRUM_SECURITY` maps each **2020 Scrum Guide** event to its security activity.

Fixtures: [backlog_weak.json](fixtures/backlog_weak.json) (a reset story shipped with no security criteria; an "abuse case" written from the customer's view; nothing threat modeled at planning) and [backlog_good.json](fixtures/backlog_good.json).

**Do not rebuild the BDD runner.** The DevSecOps course already has a Gherkin runner with step definitions and a simulated app: [devsecops-course chapter 03 BDD lab](../../../../devsecops-course/03-security-requirements-and-threat-modeling/labs/bdd-security-threats/README.md). The Gherkin this lab generates is the input such a runner executes. Requirements as code with a gate are in the [requirements-as-code lab](../../../../devsecops-course/03-security-requirements-and-threat-modeling/labs/security-requirements-as-code/README.md).

## Steps

```text
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/agile-security-stories/demo.py
.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code/labs/agile-security-stories -q -p no:cacheprovider
```

1. Run the demo and read the 12 problems of the weak backlog. Fix them one by one in a copy of the file until the gate passes.
2. Rewrite `AB-1` from the attacker's view ("As an attacker, I want to guess reset tokens so that I can take over accounts") and add Given/When/Then that describe the **defense**.
3. Add a story "As an admin, I want to export all customers" with no abuse case. The gate fails at Definition of Ready, before any code is written.
4. Copy the generated Gherkin into the DevSecOps BDD lab's `features/` folder and write the missing step definitions there.

## Expected output (real run of demo.py)

```text
== Security activities per Scrum event ==
  Sprint                         Security work is part of the Sprint Goal and the Definition of Done, not a separate phase.
  Sprint Planning                Threat model each security-relevant story (what can go wrong?) and add abuse cases and SEC: acceptance criteria before it is pulled in.
  Daily Scrum                    Raise security blockers early (a new data flow, a secret needed, a failing security test).
  Sprint Review                  Demo the security acceptance criteria and show the security test results to stakeholders.
  Sprint Retrospective           Review security findings and escaped defects; turn them into process actions.
  Backlog refinement (activity)  Write security stories and abuse cases; size security work with the team.

== backlog_weak.json: 12 problems, gate exit code 1 ==
  - US-1: security-relevant story has no SEC: acceptance criterion
  - US-2: security-relevant story has no abuse case (Definition of Ready)
  - US-2: security-relevant story has no SEC: acceptance criterion
  - US-4: not in 'As a <role>, I want <goal> so that <benefit>' form
  - US-4: security-relevant story has no abuse case (Definition of Ready)
  - US-4: security-relevant story has no SEC: acceptance criterion
  - AB-1: abuse case must be written from an attacker's point of view
  - AB-1: abuse case has no mitigating story
  - AB-1: abuse case cannot become a test (needs given/when/then)
  - US-1: pulled into the Sprint without threat modeling at Sprint Planning
  - US-2: pulled into the Sprint without threat modeling at Sprint Planning
  - US-1: marked done but security tests have not passed (Definition of Done)

== backlog_good.json: 0 problems, gate exit code 0 ==

== Gherkin generated from the good backlog's abuse cases ==
Feature: Abuse cases from the threat model

  @threat-AB-1 @spoofing
  Scenario: AB-1 is blocked (US-1)
    Given a reset token was issued for "alice"
    When I try 1000 random tokens
    Then every attempt fails and further attempts get status 429

  @threat-AB-2 @information-disclosure
  Scenario: AB-2 is blocked (US-2)
    Given I am logged in as "mallory"
    When I request the CSV export for customer "alice"
    Then the response status is 403

  @threat-AB-3 @denial-of-service
  Scenario: AB-3 is blocked (SEC-1)
    Given the reset form is public
    When I send 100 reset requests for "bob"
    Then only 5 emails are sent
```

## Run the real tool (hedged)

- **Jira / Azure Boards / GitLab issues:** keep `SEC:` criteria and an "abuse case" issue type or label; use a JQL or API query in CI to find security-relevant stories with no linked abuse case (the same check as `check_backlog`). Field names depend on your tracker.
- **pytest-bdd** or **behave**: put the generated `.feature` file in your test folder and implement the steps against a test instance. `pytest --gherkin-terminal-reporter` (pytest-bdd) or `behave --tags=@threat-AB-2` (behave) run a subset (verify flags).
- **OWASP ASVS 5.0** and the **OWASP Cornucopia** / **Elevation of Privilege** cards are good sources for abuse cases.

## What you learned

- Security requirements in agile are stories and acceptance criteria, not a separate document.
- An abuse case is a user story told by the attacker; its Given/When/Then describe the defense, so it becomes a test.
- Scrum already has the right moments: threat model at Sprint Planning, show security results at the Sprint Review, improve at the Retrospective.
- Definition of Ready and Definition of Done are where the gate lives.
