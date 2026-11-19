# Lab: Conflict triage (Thomas-Kilmann modes, Glasl stages, conflicting priorities)

**Course items:** "Handling Conflicting Priorities Among Teams", "Exploring conflict management framework", "Exploring types and patterns of conflicts", "Deescalating levels of conflict". Lessons: [01](../../01-agile-communication-and-priorities.md), [02](../../02-conflict-management.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fictional workplace scenarios; no personal data.

## Goal

Practise three quick judgements a security champion makes many times a week:

1. **What mode is this person using?** (Thomas-Kilmann: competing, collaborating, compromising, avoiding, accommodating.)
2. **How escalated is this conflict?** (Glasl's nine stages, in three levels: win-win 1–3, win-lose 4–6, lose-lose 7–9.)
3. **What mode should I choose?** (based on stakes, relationship and urgency)

And one prioritisation judgement: when teams pull in different directions, rank the work with **risk scores**, **MoSCoW** and **RICE** instead of with volume or seniority.

## Concept

[triage.py](triage.py):

| Function | What it does |
|---|---|
| `classify_mode(text)`, `glasl_stage(text)` | A deliberately simple keyword "baseline bot". Real conflicts are not keyword problems; the bot exists so you can compare your judgement with something mechanical. |
| `recommend_mode(stakes, relationship, urgency)` | A simplified decision rule from Thomas-Kilmann guidance |
| `score_answers(your_answers, key)` | **The exercise.** Scores your answers against [fixtures/answer_key.json](fixtures/answer_key.json) and prints the explanation for each miss (a stage within one of the key counts as correct) |
| `risk_score`, `moscow`, `rice` | Prioritisation helpers for conflicting priorities |

## Run

```text
.venv/Scripts/python appsec-course/17-agile-communication-and-soft-skills/labs/conflict-triage/demo.py
.venv/Scripts/python -m pytest appsec-course/17-agile-communication-and-soft-skills/labs/conflict-triage -v
```

## Expected output (real run)

```text
1. Baseline bot vs answer key
   id   bot mode       key mode       bot stage key stage  recommended (rule = key?)
   S01  competing      competing              1         1  collaborating (yes) [win-win]
   S02  avoiding       avoiding               1         1  competing (yes) [win-win]
   S03  collaborating  collaborating          1         1  collaborating (yes) [win-win]
   S04  compromising   compromising           2         2  compromising (yes) [win-win]
   S05  accommodating  accommodating          1         1  collaborating (yes) [win-win]
   S06  competing      competing              4         4  collaborating (yes) [win-lose]
   S07  competing      competing              3         3  competing (yes) [win-win]
   S08  competing      competing              6         6  competing (yes) [win-lose]
   S09  avoiding       avoiding               5         5  collaborating (yes) [win-lose]
   S10  accommodating  accommodating          1         1  accommodating (yes) [win-win]
   S11  collaborating  collaborating          1         1  collaborating (yes) [win-win]
   S12  compromising   compromising           2         2  compromising (yes) [win-win]

2. Scoring an example learner's answers
   score 31/36 (stage within 1 counts as correct)
   - S01 recommended: you said 'competing', key says 'collaborating'. He is competing (insists, refuses to discuss). The issue matters and the relationship continues, and the tool is internal, so there is time: collaborate on a scoped fix that fits his release plan, with the risk and an owner written down.
   - S02 recommended: you said 'collaborating', key says 'competing'. Ignoring emails and skipping meetings is avoiding. A certificate that expires in two days is urgent and high-stakes: be assertive, go to the accountable owner (RACI), and get it renewed now; repair the relationship afterwards.
   - S05 recommended: you said 'accommodating', key says 'collaborating'. Giving in to keep the peace is accommodating. Input validation is a high-stakes control, so accommodating is the wrong mode: bring the abuse case and ASVS requirement, and agree a minimal version together.
   - S08 stage: you said 8, key says 6. An ultimatum ('or else') is Glasl stage 6, strategies of threat. Do not sign under pressure: assertively route the exception to the accountable risk owner with the facts; at stage 6 a manager or mediator should step in.
   - S08 recommended: you said 'accommodating', key says 'competing'. An ultimatum ('or else') is Glasl stage 6, strategies of threat. Do not sign under pressure: assertively route the exception to the accountable risk owner with the facts; at stage 6 a manager or mediator should step in.

3. Conflicting priorities: one sprint, five asks
   risk 25  Fix BOLA on /orders/{id} (internet-facing)
   risk 31  Upgrade library on KEV list
   risk  9  DPDP consent logging
   risk  0  New loyalty-points feature
   risk  0  Dark mode for admin UI
   MoSCoW: {'must': ['Fix BOLA on /orders/{id} (internet-facing)', 'Upgrade library on KEV list', 'DPDP consent logging'], 'should': [], 'could': ['New loyalty-points feature'], 'wont': ['Dark mode for admin UI']}
   RICE loyalty feature: 2000.0 | RICE dark mode: 18.0
```

## Steps

1. **Before** looking at the key, read the 12 scenarios in [fixtures/scenarios.json](fixtures/scenarios.json) and write your answers in a copy of [fixtures/my_answers_example.json](fixtures/my_answers_example.json) (save it as `fixtures/my_answers.json`).
2. Score yourself in a Python shell: `t.score_answers(t.load("fixtures/my_answers.json"), t.load("fixtures/answer_key.json"))`. Read every explanation, especially where your recommended mode differs.
3. The example learner chose "accommodating" for S05 and S08. Why is accommodating dangerous for security controls and under ultimatums?
4. Write a 13th scenario from your own DBA or SOC experience (anonymised) with your answer and explanation, and add it to both files. Does the baseline bot get it right? Why not?
5. In the priorities section, why does the regulatory DPDP item become a "must" even with a low risk score? Where would you put a high-RICE feature that conflicts with a KEV patch?

## What you learned

- Naming the mode and the stage turns an emotional situation into a decision: "this is stage 4, we need a facilitator" is more useful than "they are being difficult".
- No mode is always right. Competing is correct in an active incident; accommodating is correct for low-stakes items; collaborating is the default for high-stakes, ongoing relationships.
- Prioritise security work with shared, visible criteria (risk, regulation, value per effort), so a conflict about priorities becomes a conversation about numbers.

## Run the real tool (hedged)

- The **Thomas-Kilmann Conflict Mode Instrument (TKI)** is a commercial self-assessment (Myers-Briggs Company; verify availability). Many organisations offer it through HR.
- **Glasl's model** is described in Friedrich Glasl's books on conflict management (for example *Confronting Conflict*); use it as a map, not a test.
- RICE (Intercom), MoSCoW (DSDM) and WSJF (SAFe) are free frameworks; your team's backlog tool (Jira, Azure Boards) can hold the scores as custom fields.
