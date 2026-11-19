# Lab: Managing threat models: documentation, backlog, bugs and tickets, code, automation

**Course topics:** [CTMP 4] "How To Manage Threat Models", "Documentation", "Backlog", "Bugs, and Tickets", "Code", "Automation". Lesson: [01 Managing threat models](../../01-managing-threat-models.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** JSON fixtures; the "tracker" is a Python dict. Only test systems you own or have written permission to test.

## Goal

Keep a threat model alive after the workshop: export threats to the backlog **without duplicates**, pick the right ticket type, catch **drift** between the model and the tracker, check that mitigations point at **code and tests that exist**, generate the **document**, and fail the pipeline when something is wrong.

## Concept

[tm_manage.py](tm_manage.py), working on [fixtures/threats.json](fixtures/threats.json):

| Function | Management topic | What it shows |
|---|---|---|
| `naive_sync` vs `sync` | Backlog | The naive export creates a ticket per open threat on **every** run; `sync` is an idempotent upsert keyed by a stable `fingerprint` |
| `fingerprint`, `dedupe` | Backlog | Two titles that differ in case and punctuation are the same threat; keep the higher severity |
| `ticket_type` | Bugs, and tickets | Design gap → Story, vulnerability in code → Bug, accepted risk → Risk acceptance (owner + expiry) |
| drift notes | Bugs, and tickets | Ticket closed but threat still open → REOPENED; model says mitigated but ticket open → DRIFT; acceptance expired |
| `check_code_links` | Code | A mitigated threat must name the code or test that implements it, and the file must exist |
| `to_markdown` | Documentation | The living document is generated from the model, never hand-edited |
| `ci_gate` | Automation | Exit 1 on an open High threat, a reopened ticket, an expired or invalid acceptance, or a broken code link |

## Steps

```text
.venv/Scripts/python appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-model-management/demo.py
.venv/Scripts/python -m pytest appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-model-management -q -p no:cacheprovider
```

1. Run the demo: 6 naive tickets for what is really one open threat, versus 2 managed tickets that stay 2 after three runs.
2. Change T1's severity to Medium and re-sync: the ticket is **updated**, not duplicated.
3. Rename `src/rate_limit.py` back to `src/ratelimit.py` in the demo's `REPO` set: the broken-link finding disappears. In a real pipeline this list comes from `git ls-files`.
4. Give T5 a new `accept_expires` date in 2027 and an approver in your process; the EXPIRED note disappears.

## Expected output (real run of demo.py)

```text
== Naive export: run the model three times ==
  6 tickets for 2 open threats (duplicates)

== Managed sync: three runs ==
  run 1: 2 tickets; notes: ['created Bug TM-178d0885b0', 'created Risk acceptance TM-fbeba3cf9d', 'EXPIRED acceptance TM-fbeba3cf9d: review the risk again']
  run 2: 2 tickets; notes: ['EXPIRED acceptance TM-fbeba3cf9d: review the risk again']
  run 3: 2 tickets; notes: ['EXPIRED acceptance TM-fbeba3cf9d: review the risk again']

== Someone closes the BOLA ticket without fixing it ==
   REOPENED TM-178d0885b0: ticket closed but the model still shows the threat open (verify the fix)
   EXPIRED acceptance TM-fbeba3cf9d: review the risk again

== Code links ==
   T4: reference src/ratelimit.py does not exist (renamed or deleted?)
   T6: mitigated but no code or test reference

== Generated documentation ==
# Threat model: Shop

Open 1, mitigated 3, accepted 1.

| Id | Component | STRIDE | Threat | Severity | Status |
|---|---|---|---|---|---|
| TM-178d0885b0 | Orders API | Elevation of Privilege | BOLA: order id not checked against the caller | High | open |
| TM-998a68d7be | Web App | Spoofing | No MFA for admin login | High | mitigated |
| TM-fbeba3cf9d | Orders DB | Information Disclosure | Backups not encrypted | Medium | accepted |
| TM-85415d7ed8 | Web App | Denial of Service | Reset form can be flooded | Medium | mitigated |
| TM-620b2494f0 | Mailer | Repudiation | No record of who changed email templates | Low | mitigated |

CI gate exit code: 1
```

## Run the real tool (hedged)

- **Jira / Azure DevOps / GitLab issues:** use the REST API to search for a custom field or label holding the fingerprint (`labels = TM-178d0885b0`), create only when not found, and write the ticket key back into the model. Verify field names and API versions for your tracker.
- **Threagile** keeps risk tracking (status, justification, ticket id) inside the YAML model; **IriusRisk** and other platforms have built-in Jira/Azure DevOps integrations (verify editions).
- **pytm** has `--json`; post-process it into tickets with the same fingerprint idea.

## What you learned

- A threat model is managed like code and like a backlog at the same time.
- Stable fingerprints prevent ticket spam; drift detection keeps the model and the tracker honest.
- A mitigation is only real if it points at code and a test that still exist.
