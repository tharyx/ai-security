# Lesson 03: Breakout Session: Identify Threats for a Multi-Tiered Application

**Syllabus item covered:** [CTMP 1] "Breakout Sessions to Identify Threats for a Multi-Tiered Application".

**Time:** 60 to 90 minutes (alone or in a group). **Lab:** [multi-tier-breakout](labs/multi-tier-breakout/README.md).

In a live course the breakout session is a group exercise: teams get an architecture, list threats for 30 minutes, then compare with the instructor. This lesson turns it into a **structured exercise with an answer key and a checker**, so you can do it alone and get feedback.

## 1. The system

ShopCo's orders platform (fictional), as in the [trust boundary diagram](../../images/aps-ch03-trust-boundaries-attack-surface.svg):

| Tier | Element | Zone |
|---|---|---|
| Presentation | Customer browser / app (external) | internet |
| Web | Web tier / reverse proxy (process) | dmz |
| Application | Orders API, fulfilment worker (processes); order events queue (store) | app |
| Data | Orders database, audit log (stores) | data |
| Others | Payment provider (external, sends webhooks), support admin on corp VPN (external) | third-party, corp |

The flows F1 to F10 are in [`fixtures/system.json`](labs/multi-tier-breakout/fixtures/system.json).

## 2. How to run the session

1. **Five minutes: read the model.** Run `demo.py` first only for the boundary and attack-surface lists (stop before the team results), or work them out yourself.
2. **Twenty minutes: list threats.** Copy [`template.json`](labs/multi-tier-breakout/fixtures/submissions/template.json) to `my_team.json`. For each tier ask the six STRIDE questions; for each boundary crossing ask "what must be checked here?". Every threat needs an element (or flow id), a STRIDE letter, a sentence and a mitigation.
3. **Five minutes: check.** Run the checker on your file (see the lab README). It tells you which **must** threats you missed, invalid entries and unusual letters.
4. **Debrief:** for every missed threat, ask *why* you missed it. The usual answers are "it is internal", "the provider is trusted" and "we only thought about the website".

## 3. Prompts per tier (use them if you are stuck)

- **Customer / web tier:** account takeover, session theft, traffic interception, floods, verbose errors.
- **API:** object-level authorization (the query missing `WHERE owner_id = :me`), injection, mass assignment, who did what (refund audit).
- **Queue and worker:** who can publish? does the worker trust message content? what happens with a poison message? what DB grants does the worker have?
- **Database and audit log:** backups and replicas, encryption at rest, who can edit audit records.
- **Third parties and admins:** forged webhooks, phished admins, refunds without a second approver.

## 4. Typical findings (after you try)

<details>
<summary>Open only after your own attempt</summary>

The ten **must** threats in the key: credential stuffing (customer/S), interception on F1 (I), HTTP flood on the web tier (D), BOLA in the API (E), SQL injection in the API (T), refund approvals not attributable (api/R), database or backup exposure (db/I), forged queue messages (queue/T), forged payment webhook (payment_provider/S), phished admin (admin/S).

Team A in the fixtures stayed on the web tier and scored 27 %; team B covered all tiers and scored 80 %.
</details>

## 5. What the exercise teaches

- Most missed threats sit **behind** the first tier: queues, workers, webhooks and admin paths.
- **Inside a zone is not trusted:** the queue flows F4/F5 cross no boundary but still need authentication.
- A threat without a mitigation is half a finding; the checker treats it as an error.
- STRIDE per element keeps you systematic; an unusual letter is allowed if you can justify it.

Next: [chapter 04](../04-threat-modeling-methods-and-rating/README.md) teaches the methods (DFDs, STRIDE, attack trees, personas) and rating in depth.
