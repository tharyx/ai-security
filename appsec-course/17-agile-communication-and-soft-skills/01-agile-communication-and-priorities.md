# Lesson 01: Agile Communication, Collaboration and Conflicting Priorities

**Syllabus items covered:** "The need for Agile communication and collaboration", "Handling Conflicting Priorities Among Teams" ([CSC 7]).

**Time:** 60 minutes. **Labs:** [conflict-triage](labs/conflict-triage/README.md) (priorities section), [role-play-workbook](labs/role-play-workbook/README.md) scenarios 1, 2 and 8.

> **Already in the repo.** [cybersecurity-track module 12](../../cybersecurity-track/12-soft-skills/README.md) teaches security communication for a SOC/cloud role: [plain-language risk explanations and executive summaries](../../cybersecurity-track/12-soft-skills/01-communication-and-executive-summaries.md), [escalation and handover](../../cybersecurity-track/12-soft-skills/03-escalation-handover-and-on-call.md) and [working with IT and DevOps, influence without authority](../../cybersecurity-track/12-soft-skills/04-working-with-it-devops-and-influence.md). Read those first if you have not. This lesson adds the **agile team** setting of a security champion.

## 1. The need for agile communication and collaboration

Agile teams ship every one or two weeks. Security that arrives as a 40-page report after the release does not fit. A champion's job is to make security part of the team's **normal conversations**:

| Agile event (Scrum Guide 2020) | Security champion's contribution |
|---|---|
| Backlog refinement | Add abuse cases and security acceptance criteria to stories; flag stories that need a threat model |
| Sprint Planning | Make security work visible and sized like any other work; agree the security part of the definition of done |
| Daily Scrum | Raise blockers early (a failing gate, a secret found); keep it short |
| Sprint Review | Show security outcomes too ("BOLA tests added for all id routes") |
| Sprint Retrospective | Discuss gate noise, near misses, what to automate next; blameless |

Principles for agile security communication:

1. **Early and small** beats late and big: a comment on a story in refinement costs minutes; a pentest finding after release costs days.
2. **In the team's tools and language:** tickets in their backlog, comments in their merge requests, examples in their framework. Not a separate security portal.
3. **Face to face (or a call) for anything controversial;** chat is for facts. Text strips tone and escalates conflict.
4. **Explain risk in business terms** (customers affected, money, regulation, downtime), bottom line first. See [module 12 lesson 01](../../cybersecurity-track/12-soft-skills/01-communication-and-executive-summaries.md).
5. **Listen first.** Understand the team's goals and constraints before proposing a control.
6. **Make the secure way the easy way:** templates, libraries, pipeline rules. Collaboration is also about reducing work for the team.

**Why collaboration matters:** security people are outnumbered (often 1 per 50–100 developers). Without the teams' cooperation, nothing gets fixed. Champions exist because influence travels better inside a team than from outside it (see [chapter 01](../01-security-champions-and-appsec-basics/README.md) on the champions programme).

## 2. Handling conflicting priorities among teams

Conflicts about priorities are normal: product wants features, operations wants stability, security wants risk reduction, compliance wants evidence, and everyone has a deadline. The champion's job is not to win, but to make the trade-off **visible, comparable and decided by the right person**.

### 2.1 A five-step method

1. **Clarify each ask:** what exactly, by when, and what happens if it slips? Separate deadlines that are real (regulation, contract) from preferences.
2. **Use shared criteria:** risk (likelihood × impact, exposure, known exploitation), regulatory or contractual obligation, customer value, effort, dependencies.
3. **Score and rank together**, in the open, with one of the frameworks below.
4. **Offer options, not ultimatums:** reduce scope (minimal fix now, full fix later), add compensating controls (a WAF rule, a feature flag off), resequence, or accept the risk formally.
5. **Escalate to the decision owner** with a one-page summary when teams cannot agree. The product owner decides product priority; the risk owner accepts risk. Record the decision, the owner and a review date.

### 2.2 Prioritisation frameworks

| Framework | How it works | When to use it |
|---|---|---|
| **Risk-based** | Likelihood × impact, raised for internet exposure and known exploitation (CISA KEV), lowered for compensating controls | Security findings and fixes |
| **MoSCoW** | Must, Should, Could, Won't (this time) | Release scoping; quick agreement with product owners |
| **RICE** | Reach × Impact × Confidence ÷ Effort | Comparing features and improvements by value per effort |
| **WSJF** (SAFe) | Cost of delay ÷ job size | Programme-level backlogs |
| **Eisenhower** | Urgent/important matrix | Your own week as a champion |
| **SLA-driven** | Fix-time targets per severity (for example critical 7–15 days, high 30 days; set by policy) | Vulnerability management at scale |

The [conflict-triage lab](labs/conflict-triage/README.md) implements risk scores, MoSCoW and RICE.

### 2.3 Typical security vs feature conflicts and good answers

- **"Fix it next quarter."** Show exploitability and exposure; offer a minimal fix or compensating control now; if declined, a written risk acceptance by the owner with a date.
- **"The gate is blocking our release."** Look at the finding together; if it is a false positive, tune the rule; if real, offer the fastest safe path; never quietly disable the gate.
- **"Two security teams ask for opposite things"** (for example, the platform team wants gateway auth, AppSec wants in-app checks). Usually both are right at different layers; write a short design decision record.

## 3. Scenario: the loyalty feature and the KEV patch

A KEV-listed vulnerability in an HTTP library affects the internet-facing checkout API. The same sprint must deliver a loyalty feature that marketing has announced. The product owner says no to the patch. The champion brings a one-page comparison: the patch is two hours of work plus a regression run; exploitation is active in the wild; impact is customer card data (PCI DSS). The feature scores high on RICE but its date is a marketing choice, not a contract. The product owner agrees to patch first and move one small loyalty story to the next sprint. The decision and the reasons are recorded in the sprint notes.

## 4. Checklist

- [ ] I can say what a champion does in each Scrum event.
- [ ] I can list six principles of agile security communication.
- [ ] I can run the five-step method for conflicting priorities.
- [ ] I can explain risk-based, MoSCoW and RICE prioritisation, and when to use each.

## References

- The 2020 Scrum Guide (scrumguides.org).
- OWASP Security Champions Guide (verify current version); OWASP SAMM "Education & Guidance".
- Intercom's RICE article; DSDM MoSCoW; SAFe WSJF.
- Repo: [cybersecurity-track 12 soft skills](../../cybersecurity-track/12-soft-skills/README.md), [chapter 05 Scrum events and security requirements](../05-agile-threat-modeling-as-code/README.md).
