# Chapter 17: Agile Communication and Soft Skills

A security champion's hardest problems are often not technical: getting security work into a full sprint, settling conflicting priorities between teams, calming an escalating argument, holding people accountable without blame, and staying both empathetic and firm. This chapter gives you frameworks for each (Scrum events, risk-based/MoSCoW/RICE prioritisation, Thomas-Kilmann modes, Glasl's escalation stages, RACI, DESC and NVC) and practice through a scored conflict-triage exercise and a role-play workbook with model answers.

> **Safety.** The labs use fictional workplace scenarios only. Never use real colleagues' names or details in practice notes. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Models and tools are hedged: **verify at the source**.

## Syllabus coverage

Source: **[CSC 7]** Security Champion course, chapter 7 "Agile Communications, Collaboration, and Soft Skills". Every line is listed verbatim and in source order.

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CSC 7] The need for Agile communication and collaboration | [Lesson 01 section 1](01-agile-communication-and-priorities.md#1-the-need-for-agile-communication-and-collaboration); [cybersecurity-track 12 lesson 01](../../cybersecurity-track/12-soft-skills/01-communication-and-executive-summaries.md) | [role-play-workbook](labs/role-play-workbook/README.md) scenarios 1 and 8 |
| [CSC 7] Handling Conflicting Priorities Among Teams | [Lesson 01 section 2](01-agile-communication-and-priorities.md#2-handling-conflicting-priorities-among-teams) | [conflict-triage](labs/conflict-triage/README.md) (risk, MoSCoW, RICE); [role-play-workbook](labs/role-play-workbook/README.md) scenario 2 |
| [CSC 7] Exploring conflict management framework | [Lesson 02 section 1](02-conflict-management.md#1-exploring-the-conflict-management-framework-thomas-kilmann) (SVG) | [conflict-triage](labs/conflict-triage/README.md) (Thomas-Kilmann modes) |
| [CSC 7] Exploring types and patterns of conflicts | [Lesson 02 section 2](02-conflict-management.md#2-exploring-types-and-patterns-of-conflicts) | [role-play-workbook](labs/role-play-workbook/README.md) scenario 3 |
| [CSC 7] Deescalating levels of conflict | [Lesson 02 section 3](02-conflict-management.md#3-de-escalating-levels-of-conflict-glasls-nine-stages) | [conflict-triage](labs/conflict-triage/README.md) (Glasl stages); [role-play-workbook](labs/role-play-workbook/README.md) scenario 4 |
| [CSC 7] Holding people accountable for security | [Lesson 03 section 1](03-accountability-empathy-and-champion-traits.md#1-holding-people-accountable-for-security); [blameless culture](../../cybersecurity-track/12-soft-skills/04-working-with-it-devops-and-influence.md#21-what-blameless-means) | [role-play-workbook](labs/role-play-workbook/README.md) scenario 5 |
| [CSC 7] Staying empathetic and assertive | [Lesson 03 section 2](03-accountability-empathy-and-champion-traits.md#2-staying-empathetic-and-assertive) | [role-play-workbook](labs/role-play-workbook/README.md) scenario 6 (DESC) |
| [CSC 7] Security Champion’s Skills and Traits | [Lesson 03 section 3](03-accountability-empathy-and-champion-traits.md#3-security-champions-skills-and-traits); champions programme in [chapter 01](../01-security-champions-and-appsec-basics/README.md) | [role-play-workbook](labs/role-play-workbook/README.md) scenario 7 |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "Agile communication" without a reference | The **2020 Scrum Guide** is the current Scrum definition (Sprint, Sprint Planning, Daily Scrum, Sprint Review, Sprint Retrospective; product goal and definition of done as commitments). |
| Security champion skills (no source) | The **OWASP Security Champions Guide** (ten principles) is the main open reference; typical models: one champion per team with about 10–20% protected time, a community of practice and recognition. |
| Course chat support | The course's chat community (check your course portal) is a logistics item, not a skill; this chapter does not depend on it. |

## How the three courses overlap here

- **CSC 7 only** owns this chapter. The Threat Modeling course touches agile ceremonies in [chapter 05](../05-agile-threat-modeling-as-code/README.md) (Scrum events and security requirements); this chapter focuses on the people side.
- The repo's [cybersecurity-track module 12](../../cybersecurity-track/12-soft-skills/README.md) already teaches communication, executive summaries, escalation, blameless working with DevOps and influence for a SOC role. Lessons here link to it and add agile teams, conflict models and accountability.

## Learning order

1. [Lesson 01](01-agile-communication-and-priorities.md) (read module 12 lessons 01 and 04 first if new to you). About 1 hour.
2. [Lesson 02](02-conflict-management.md), then the [conflict-triage lab](labs/conflict-triage/README.md). About 2 hours.
3. [Lesson 03](03-accountability-empathy-and-champion-traits.md), then the [role-play-workbook](labs/role-play-workbook/README.md), ideally with a partner. About 3 hours.
4. Then go back to the [course front page](../README.md) and plan your exam path.

## Lab index

All Python labs run offline: `.venv/Scripts/python -m pytest appsec-course/17-agile-communication-and-soft-skills -q -p no:cacheprovider`.

| Lab | Course topics | Tests |
|---|---|---|
| [conflict-triage](labs/conflict-triage/README.md) | Conflicting priorities; conflict management framework; de-escalation levels | 8 |
| [role-play-workbook](labs/role-play-workbook/README.md) | All eight topics as eight conversations with model answers | n/a (speaking and writing practice) |

## Exam tips

- **Thomas-Kilmann:** two axes (assertiveness, cooperativeness), five modes. No mode is always right; know when each fits.
- **Collaborate** on high-stakes issues with time; **compete** only in real urgency, then repair; never **avoid** as a way to accept risk.
- **Glasl:** 9 stages, 3 levels (win-win 1–3, win-lose 4–6, lose-lose 7–9). From stage 4, bring in a facilitator.
- **Conflicting priorities:** shared criteria (risk, regulation, value, effort), options, and the decision goes to the owner.
- **Accountability = one owner + date + visibility + follow-through,** not blame. RACI has exactly one "A".
- **Assertive ≠ aggressive.** DESC: Describe, Express, Specify, Consequences.
- **Champion traits:** curiosity, credibility, communication, empathy, teaching, pragmatism, persistence, integrity.

## Interview / exam questions

<details>
<summary>1. Why do agile teams need a different style of security communication?</summary>

They ship every one or two weeks. Security must arrive early and in small pieces inside their own ceremonies and tools (refinement, planning, definition of done, merge requests), not as a late report. Otherwise it is ignored or becomes a blocker.
</details>

<details>
<summary>2. What does a security champion contribute to each Scrum event?</summary>

Refinement: abuse cases and security acceptance criteria. Planning: visible, sized security work and definition of done. Daily Scrum: early blockers. Review: show security outcomes. Retrospective: gate noise, near misses, what to automate.
</details>

<details>
<summary>3. Two teams want opposite things this sprint. What do you do?</summary>

Clarify each ask and its real deadline, compare them with shared criteria (risk, regulation, value, effort), offer options (scope reduction, compensating controls, resequencing), and let the owner of the priority decide, with the decision and its reason recorded. Do not take sides.
</details>

<details>
<summary>4. Explain the Thomas-Kilmann model.</summary>

Responses to conflict plotted on assertiveness (own concerns) and cooperativeness (other's concerns), giving five modes: competing, collaborating, compromising, avoiding, accommodating. Each fits certain situations; overusing any one causes problems.
</details>

<details>
<summary>5. When is competing the right mode for a security champion?</summary>

In real urgency with high stakes: an active incident, a critical exposure, an expiring certificate on a production API. Decide or escalate quickly, then repair the relationship and review the process afterwards.
</details>

<details>
<summary>6. Why is accommodating risky for security issues?</summary>

It gives up your concern to keep the peace. On low-stakes items it builds goodwill, but on controls that protect customers it silently accepts risk that you do not own.
</details>

<details>
<summary>7. Name types of conflict and which one usually hurts teams most.</summary>

Task/content, process, relationship, status/role, values and resource conflicts. Relationship conflict hurts most; task conflict handled well can improve decisions, but turns into relationship conflict when people feel attacked.
</details>

<details>
<summary>8. What is a recurring conflict a sign of, and how do you fix it?</summary>

A missing or unclear process (for example no agreed severity rule for WAF alerts). Fix the process with the people involved, rather than settling each instance.
</details>

<details>
<summary>9. Describe Glasl's model and how you would de-escalate at stage 2 and stage 6.</summary>

Nine stages in three levels: win-win (1 hardening, 2 debate, 3 actions not words), win-lose (4 coalitions, 5 loss of face, 6 threats), lose-lose (7–9). At stage 2: separate facts from opinions, summarise the other side, agree criteria, move to a call. At stage 6: do not act under threat, route the decision to its accountable owner, involve managers or a mediator.
</details>

<details>
<summary>10. How do you hold people accountable for security without creating fear?</summary>

Clear ownership (RACI, service catalogue), agreed SLAs, visible dashboards, a pre-agreed escalation path, private conversations about misses and public recognition of good work, and blameless reviews that fix systems. Just culture still addresses reckless choices.
</details>

<details>
<summary>11. What is the difference between blameless and ownerless?</summary>

Blameless means reviews look for system causes instead of punishing individuals. Every risk and fix still has one named accountable owner and a date.
</details>

<details>
<summary>12. Give a DESC script for a developer who keeps disabling certificate checks.</summary>

Describe: "Two releases shipped with verify=False in the payments client." Express: "I'm worried payment calls can be intercepted." Specify: "Can we add the test CA to the test trust store and a SAST rule blocking verify=False outside tests?" Consequences: "Then nobody has to remember it and tests still pass."
</details>

<details>
<summary>13. What is the difference between assertive and aggressive communication?</summary>

Assertive states facts, your needs and a clear request while respecting the other person ("I need this fixed before go-live because customer data is exposed; can we find a way?"). Aggressive attacks the person or demands without listening ("Your code is insecure, fix it today").
</details>

<details>
<summary>14. What skills and traits make a good security champion?</summary>

Curiosity and continuous learning, technical credibility in the team's stack, clear communication, empathy and assertiveness, teaching, pragmatism, persistence, integrity, systems thinking, and knowing when to escalate.
</details>

<details>
<summary>15. What should an organisation give its security champions?</summary>

A management mandate, protected time (often 10–20%), a training path, a community of practice, recognition and career credit, access to the security team, and metrics that show their impact.
</details>

## References

- The 2020 Scrum Guide; OWASP Security Champions Guide (verify current version); OWASP SAMM.
- Thomas and Kilmann, *Thomas-Kilmann Conflict Mode Instrument*; Glasl, *Confronting Conflict*; Fisher, Ury and Patton, *Getting to Yes*; Rosenberg, *Nonviolent Communication*; Bower and Bower, *Asserting Yourself*.
- Google SRE book (postmortem culture); Dekker, *Just Culture*.
- Repo: [cybersecurity-track 12 soft skills](../../cybersecurity-track/12-soft-skills/README.md) and its [templates](../../cybersecurity-track/12-soft-skills/templates/).

**Next:** back to the [course front page](../README.md).
