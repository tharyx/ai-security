# Lab: Security champion role-play workbook

**Course items:** all eight [CSC 7] topics, practised as conversations. Lessons: [01](../../01-agile-communication-and-priorities.md), [02](../../02-conflict-management.md), [03](../../03-accountability-empathy-and-champion-traits.md). Templates for written follow-ups: [cybersecurity-track 12 templates](../../../../cybersecurity-track/12-soft-skills/templates/).

**Time:** 2 hours (alone: write your answers; with a partner: role-play each one for 5–10 minutes). **Tests:** none, this is a speaking and writing workbook. **Safety:** fictional situations; never use real colleagues' names in practice notes.

## How to use it

1. Read the situation. Write what you would **say** (first two or three sentences, word for word) and what you would **do** next.
2. With a partner: one person plays the other role using the "how they react" note; swap roles after each scenario.
3. Only then open the model answer and compare. The model answers use the tools from the lessons: **DESC** (Describe, Express, Specify, Consequences), **NVC** (observation, feeling, need, request), **"yes, if"**, **RACI**, Thomas-Kilmann modes and Glasl stages.
4. Score yourself 1–5 on: clear ask, respect, facts not blame, a next step with an owner and date.

---

## Scenario 1: The sprint is full (agile communication)

**Situation.** In sprint planning you ask the orders team to add "fix BOLA on `GET /orders/{id}`" (found by your test suite). The product owner says the sprint is full with the loyalty feature promised to marketing.

**How they react.** Defensive: "Security always arrives at planning with surprises."

<details>
<summary>Model answer</summary>

**Say:** "You're right that this is late, and that's on me: I should have raised it in refinement. Here's the risk in one line: any logged-in customer can read any other customer's orders, including addresses. Can we look at it for five minutes and decide together?"

**Do:** Show the risk score and the size (a one-line owner check plus a test, about half a day). Offer options: (a) swap a small story out, (b) fix in this sprint as an expedite item agreed by the PO, (c) if neither, a written risk acceptance by the product owner with a date. Agree the definition of done includes the authorization test. Afterwards, join refinement every sprint so it is not a surprise again.

**Why:** Agile communication means early, small, visible asks inside the team's own ceremonies; options and a clear risk owner instead of a demand.
</details>

## Scenario 2: Two teams, two deadlines (conflicting priorities)

**Situation.** The platform team wants every service on the new gateway this quarter. The payments team must ship a regulatory change by month end and refuses gateway work. Both ask you, the champion, to "back them" in the steering meeting.

**How they react.** Each team says the other is "not thinking about the business".

<details>
<summary>Model answer</summary>

**Say (to both, together):** "Both goals are real. Can we put them on one page with the same criteria: regulatory deadline, risk reduction, effort, dependency?"

**Do:** Score both items (risk, MoSCoW, RICE as in the conflict-triage lab). Likely result: the regulatory change is a **must** for this month; gateway onboarding for payments moves to next month with a compensating control now (rate limit and WAF rule at the existing load balancer). Take one recommendation, with the trade-off written down, to the people who own the priority (the product owners and the steering group). You inform; they decide.

**Why:** A champion does not pick sides (that escalates to Glasl stage 4, coalitions). Shared, visible criteria turn a fight about status into a decision about risk and value.
</details>

## Scenario 3: The SOC analyst and the developer (types and patterns of conflict)

**Situation.** For the third time this month a SOC analyst opens a P1 ticket for the orders API because of "SQL injection attempts" in the WAF logs. The developer closes each ticket as "false positive, WAF blocked it". They now reply to each other in capital letters.

**How they react.** The developer: "SOC wastes my time." The analyst: "Devs never take security seriously."

<details>
<summary>Model answer</summary>

**Diagnose first:** This is a recurring **process** conflict (no agreed severity rules for blocked attempts) that is turning into a **relationship** conflict (stage 2, polarised, point-scoring).

**Say (one-to-one with each, then together):** "I think you both want the same thing: real attacks found fast and no wasted time. The problem is that we never agreed what a blocked attempt means."

**Do:** Agree a rule: blocked scans are P4 and aggregated weekly; any attempt that gets a 2xx or 5xx response is P1. Add a detection that correlates WAF blocks with application errors. Thank both in the channel when the first real issue is found through the new rule.

**Why:** Fix the pattern (process), not just the incident; de-escalate at stage 2 while dialogue is still possible.
</details>

## Scenario 4: The ultimatum (de-escalating)

**Situation.** The release manager messages you: "Sign the pen-test exception by 5 pm or I escalate to the CTO and name you as the blocker."

**How they react.** Under pressure from his own boss; short replies.

<details>
<summary>Model answer</summary>

**Say (call, not chat):** "I hear that the release date is at risk and that you're under real pressure. I want this release to go out too. I can't sign the exception myself, because I'm not the risk owner, but I can get the risk owner a one-page summary in the next hour so they can decide today."

**Do:** One page: finding, exploitability, compensating controls, options (ship with a feature flag off; ship with a WAF rule and fix in 7 days; delay). Send to the accountable owner (RACI "A") and the release manager together. If threats continue, involve both managers. At Glasl stage 6, a third party is appropriate.

**Why:** Empathy for the person, assertiveness on the decision rights. Never accept a risk you don't own; never let a threat decide a risk.
</details>

## Scenario 5: Nobody owns it (holding people accountable)

**Situation.** A critical dependency vulnerability (on the KEV list) has been open for 45 days in the reporting API. The ticket has been reassigned five times.

**How they react.** Each team lead says "it's a shared library, not ours".

<details>
<summary>Model answer</summary>

**Say:** "I'm not here to find who's to blame. I need one name next to this so it gets fixed this week. Who is accountable for the reporting API's dependencies?"

**Do:** Use the service catalogue or RACI to name the accountable owner; if none exists, raise that gap to engineering management (it is a finding in itself). Agree an SLA-based date (KEV items: for example 7–15 days by your policy). Track it on the shared dashboard. After the fix, run a short blameless review: why could ownership be unclear, and what changes in the catalogue?

**Why:** Accountability is about clear ownership and agreed SLAs, made visible, not public shaming. Blameless does not mean ownerless.
</details>

## Scenario 6: Empathy and assertiveness (DESC script)

**Situation.** A senior developer keeps merging code that disables certificate verification (`verify=False`) "just for testing", and it reached production twice.

**How they react.** "I've been coding for 15 years. Don't lecture me."

<details>
<summary>Model answer</summary>

**DESC:**
- **Describe:** "In the last two releases, `verify=False` in the payments client went to production."
- **Express:** "I'm worried, because that lets anyone on the network path read or change payment calls, and I'd hate for you to be the one called at 2 a.m."
- **Specify:** "Could we add the test certificate to the test trust store instead, and could you help me write a SAST rule that blocks `verify=False` outside test folders?"
- **Consequences:** "Then nobody has to remember it, and your tests still run."

**Do:** Ask for their expertise (they help write the rule). Offer the easy path. Add the rule to the pipeline.

**Why:** Respect experience, describe facts and impact, make a specific request, and make the secure way the easy way.
</details>

## Scenario 7: The champion's first month (skills and traits)

**Situation.** You have just been named security champion for your team with "10–20% of your time". Your manager asks what you will do in the first month.

<details>
<summary>Model answer</summary>

1. **Week 1:** Learn the team's services, data and pipeline; join the champions' community channel; read the threat model if one exists.
2. **Week 2:** One quick win: add secrets scanning to the pipeline, or fix the top SCA finding.
3. **Week 3:** Run a 45-minute threat-modeling session on the next feature (STRIDE, chapter 04).
4. **Week 4:** Share one short lesson with the team (for example "BOLA in our API, and the test that catches it"); agree how security items enter refinement and the definition of done.
5. **Ongoing:** Protect the time allocation with the manager; report two or three metrics monthly (findings fixed, time to fix, tests added).

**Traits shown:** curiosity, communication, credibility (quick win), teaching, persistence, and knowing when to escalate.
</details>

## Scenario 8: The "security is a blocker" meeting (need for collaboration)

**Situation.** In a retrospective, a developer says: "Security is the reason we missed the date. The gates fail on nonsense."

<details>
<summary>Model answer</summary>

**Say:** "Thanks for saying it openly. If the gates fail on nonsense, that's a problem I want to fix. Can we look at the last ten failures together?"

**Do:** Review the failures. Suppose six were false positives from one SAST rule: tune or disable it with a written reason. Suppose two were real (an injection, a secret): show what they would have cost. Agree a gate policy together (what blocks, what warns) and revisit in two sprints.

**Why:** Collaboration means making the developers' pain your problem. Trust in the gates is a shared asset.
</details>
