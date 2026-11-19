# Lesson 03: Accountability, Empathy and Assertiveness, and the Champion's Skills and Traits

**Syllabus items covered:** "Holding people accountable for security", "Staying empathetic and assertive", "Security Champion’s Skills and Traits" ([CSC 7]).

**Time:** 60 minutes. **Lab:** [role-play-workbook](labs/role-play-workbook/README.md) scenarios 4 to 7. Related in the repo: [blameless culture and raising findings](../../cybersecurity-track/12-soft-skills/04-working-with-it-devops-and-influence.md#21-what-blameless-means), [saying "yes, if"](../../cybersecurity-track/12-soft-skills/04-working-with-it-devops-and-influence.md#25-saying-no-and-yes-if), and the champions programme in [chapter 01](../01-security-champions-and-appsec-basics/README.md).

## 1. Holding people accountable for security

Accountability means **one named owner per risk or fix, a clear expectation, a date, visibility, and follow-through**. It does not mean blame.

### 1.1 Tools

| Tool | What it does | Example |
|---|---|---|
| **RACI** | Responsible (does it), Accountable (owns the outcome, one person), Consulted, Informed | Dependency upgrades: R = service team developer, A = service owner, C = AppSec, I = product owner |
| **Service catalogue / ownership** | Every API, repo and cloud account has an owning team | The inventory checks in [chapter 16](../16-api-security-the-devsecops-way/labs/api-asvs-at-scale/README.md) |
| **Security SLAs** | Fix-time targets by severity, agreed with engineering leadership | Critical 7–15 days, high 30, medium 90 (set by your policy) |
| **Definition of done** | Security criteria in every story | Tests for authorization, no new high SAST findings, threat model updated |
| **Risk acceptance** | The accountable owner signs, with reason and expiry | A suppression in the gate baseline (chapter 16 lab) |
| **Dashboards** | Findings and SLA status per team, visible to all | Portfolio view, overdue items highlighted |
| **Escalation path** | Agreed in advance: owner → manager → director | Overdue critical → engineering manager after the SLA |

### 1.2 Blameless but not ownerless

- **Blameless culture** (from SRE practice): after an incident, ask what in the system let it happen, not who to punish. People then report problems early.
- **Just culture:** honest mistakes are learning; reckless choices (ignoring a known critical, bypassing a gate on purpose) still have consequences.
- **Accountability conversations** use facts and agreements: "We agreed critical fixes in 15 days; this one is at 45. What is blocking you, and what date can you commit to?"
- **Recognise good behaviour publicly** (fixes, good reports); discuss misses **privately**.

As a DBA you already did this: a change ticket had an owner, an approval, a rollback plan and a post-change review. Security accountability is the same discipline.

## 2. Staying empathetic and assertive

**Empathy** is understanding the other person's situation and feelings (deadline pressure, fear of blame, pride in their code). **Assertiveness** is stating your needs and limits clearly and respectfully. A champion needs both at the same time: empathy without assertiveness gives away security; assertiveness without empathy gives away cooperation.

| Style | Sounds like | Result |
|---|---|---|
| Passive | "Maybe, if you have time, you could perhaps look at…" | Nothing changes |
| Aggressive | "Your code is insecure, fix it today." | Defensiveness, conflict |
| Passive-aggressive | Silence in the meeting, a sharp email to the manager later | Lost trust |
| **Assertive** | "I see the release pressure. I need this fixed before go-live because customer data is exposed. Can we find a way?" | Respect and action |

### 2.1 DESC script

1. **Describe** the facts, without judgement: "The last two releases shipped with certificate verification disabled."
2. **Express** the impact or your concern: "I'm worried, because payment calls can then be intercepted."
3. **Specify** what you are asking for: "Could we use the test CA in the test trust store, and add a rule that blocks `verify=False`?"
4. **Consequences** (positive first): "Then nobody has to remember it, and tests still run."

### 2.2 Nonviolent Communication (NVC, Marshall Rosenberg)

**Observation** (what happened) → **Feeling** (yours) → **Need** (what matters) → **Request** (concrete, doable, negotiable). Example: "When the gate was disabled without a ticket (observation), I felt uneasy (feeling), because I need to be able to show auditors what changed (need). Would you open a ticket next time, even after the fact (request)?"

### 2.3 Active listening and other habits

- Listen to understand, then **summarise back** before you answer.
- Ask open questions: "What would make this easier for your team?"
- Say **"yes, if"** instead of "no": "Yes, you can ship Friday, if the feature flag stays off until the fix lands."
- Admit your own mistakes quickly; it makes your assertiveness credible.
- Keep calm under pressure; take a break before replying to an angry message.

## 3. Security champion's skills and traits

The OWASP **Security Champions Guide** (an OWASP project with ten principles; verify the current list) and common programme experience describe what makes a champion effective. Champions are usually **developers, testers or ops engineers with an interest in security**, typically one per team, with about **10–20% of their time** protected for the role.

| Skill or trait | Why it matters | How to grow it |
|---|---|---|
| **Curiosity** and a learning habit | Threats and tools change every year | This course; CTF platforms; reading incident write-ups |
| **Technical credibility** in the team's stack | Developers listen to someone who knows their code | Fix real issues, write tests and rules |
| **Communication** (plain language, writing) | Risk must be understood by product owners and managers | [module 12 lesson 01](../../cybersecurity-track/12-soft-skills/01-communication-and-executive-summaries.md) |
| **Empathy and assertiveness** | Influence without authority | DESC/NVC practice (workbook) |
| **Teaching and sharing** | Multiply knowledge in the team | Short demos, lunch-and-learns, pair reviews |
| **Pragmatism** | Perfect security is not the goal; reduced risk is | Risk-based prioritisation |
| **Persistence and follow-through** | Fixes need tracking to the end | Dashboards, SLAs |
| **Knowing when to escalate** | Some decisions are above the team | RACI, Glasl stage 4+ |
| **Integrity** | Trust is the champion's main asset | Never hide findings; never shame people |
| **Systems thinking** | Fix the pattern, not just the instance | Turn each finding into a rule, test or template |

What an organisation should give champions: a mandate from management, protected time, training paths, a community of practice (a regular meeting and chat channel), recognition (and career credit), and metrics that show their impact.

## 4. Scenario: the overdue critical

A critical vulnerability in the reporting API is 45 days old against a 15-day SLA. Each team lead says the shared library is not theirs. The champion checks the service catalogue: the reporting API has no owner listed. Instead of blaming anyone, she raises the **ownership gap** with the engineering manager, who assigns the reporting team as accountable. The team lead agrees a fix date in five days; the dashboard shows it; the fix lands in four. In the blameless review the action is not "train the team" but "make the ownership field mandatory in the catalogue and alert on unowned services". The champion thanks the team lead in the champions' channel.

## 5. Checklist

- [ ] I can explain RACI and name the "A" for a security fix in my team.
- [ ] I can describe blameless and just culture, and how they fit with accountability.
- [ ] I can write a DESC script and an NVC request for a real situation.
- [ ] I can distinguish passive, aggressive, passive-aggressive and assertive replies.
- [ ] I can list ten skills and traits of a security champion and pick two to develop.

## References

- OWASP Security Champions Guide (verify current version); OWASP SAMM; the Security Champions Playbook (older, verify status).
- Google SRE book, chapter on postmortem culture; Sidney Dekker, *Just Culture*.
- Marshall B. Rosenberg, *Nonviolent Communication*; Bower and Bower, *Asserting Yourself* (origin of the DESC script).
- Repo: [cybersecurity-track 12](../../cybersecurity-track/12-soft-skills/README.md), [chapter 01 champions](../01-security-champions-and-appsec-basics/README.md).
