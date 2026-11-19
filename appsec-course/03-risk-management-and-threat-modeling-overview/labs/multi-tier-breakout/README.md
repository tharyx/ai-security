# Lab: Breakout session: threats for a multi-tiered application

**Course topics:** [CTMP 1] Breakout Sessions to Identify Threats for a Multi-Tiered Application; Trust Boundaries vs. Attack Surfaces. Lessons: [02 section 8](../../02-threat-modeling-overview.md#8-trust-boundaries-vs-attack-surfaces), [03 Breakout](../../03-breakout-multi-tier-application.md).

**Time:** 60 to 90 minutes. **Tests:** 8, all offline. **Safety:** a fictional system described in JSON; nothing is attacked. Only test systems you own or have written permission to test.

## Goal

List threats for a web + API + queue + database system, then get objective feedback against a facilitator's answer key.

## Concept

[breakout.py](breakout.py) reads [fixtures/system.json](fixtures/system.json) (zones with trust levels, elements, flows) and:

- lists **trust-boundary crossings** (any flow whose ends are in different zones, both directions),
- lists the **external attack surface** (flows that start at an external entity),
- checks a team submission against [fixtures/answer_key.json](fixtures/answer_key.json): matched threats, missing **must** threats, unknown elements, invalid STRIDE letters, threats with no mitigation, and letters unusual for the element type (STRIDE per element; log stores also get R).

A team passes when it finds every must threat, covers at least 60 % of the key, and has no errors.

## Steps

1. Copy [fixtures/submissions/template.json](fixtures/submissions/template.json) to `fixtures/submissions/my_team.json` and write your threats (20 minutes, no peeking at the key).
2. Check it: `.venv/Scripts/python appsec-course/03-risk-management-and-threat-modeling-overview/labs/multi-tier-breakout/demo.py appsec-course/03-risk-management-and-threat-modeling-overview/labs/multi-tier-breakout/fixtures/submissions/my_team.json`
3. For every missed must threat, write one line on why you missed it.
4. Add a threat that is not in the key (for example cache poisoning at the web tier). The checker lists it under "Not in the key (review, may be valid)": answer keys are not complete either.

## Run

```text
.venv/Scripts/python appsec-course/03-risk-management-and-threat-modeling-overview/labs/multi-tier-breakout/demo.py
.venv/Scripts/python -m pytest appsec-course/03-risk-management-and-threat-modeling-overview/labs/multi-tier-breakout -q -p no:cacheprovider
```

## Real output (from demo.py, the two sample teams)

```text
System: ShopCo orders platform
Trust-boundary crossings:
  F1: internet -> dmz (inbound)
  F2: dmz -> app (inbound)
  F3: app -> data (inbound)
  F6: app -> data (inbound)
  F7: third-party -> app (inbound)
  F8: corp -> app (inbound)
  F9: app -> data (inbound)
  F10: app -> third-party (outbound)
External attack surface (entry points):
  web via F1 (HTTPS: login, browse, place order)
  api via F7 (payment webhook)
  api via F8 (admin console: refunds)

--- Team A: coverage 27%, FAIL ---
Missing MUST threats:
  - K4 api/E: BOLA: user reads another user's order by changing the id
  - K6 db/I: Database or backup copy exposed
  - K7 queue/T: Forged OrderPlaced messages injected into the queue
  - K9 payment_provider/S: Forged payment webhook marks unpaid orders as paid
  - K10 admin/S: Phished admin credentials used for refunds
  - K11 api/R: No record of who approved a refund
Errors:
  - #5 web/I: NO_MITIGATION
  - #6 cdn/T: UNKNOWN_ELEMENT
  - #7 db/X: INVALID_STRIDE_LETTER
Not in the key (review, may be valid):
  - web/I
Missing optional threats:
  - K8 worker/E: Worker trusts message content and runs with DBA-level grants
  - K12 audit_log/T: Admin edits or deletes audit records
  - K13 web/S: Something other than the web tier calls the API directly
  - K14 queue/D: Poison or flood messages stall fulfilment
  - K15 F3/T: Unencrypted SQL traffic altered inside the network

--- Team B: coverage 80%, PASS ---
Missing optional threats:
  - K12 audit_log/T: Admin edits or deletes audit records
  - K13 web/S: Something other than the web tier calls the API directly
  - K15 F3/T: Unencrypted SQL traffic altered inside the network
```

## Run the real tool (hedged)

In a real breakout, draw the system in **OWASP Threat Dragon** (free, desktop or web) or on a whiteboard, and use **STRIDE per element** or a card game ([chapter 04 lesson 04](../../../04-threat-modeling-methods-and-rating/04-other-methodologies-and-games.md)) to drive discussion. Microsoft Threat Modeling Tool generates STRIDE threats from a drawn DFD automatically (Windows only; verify current support). Record results in your tracker, not in the drawing tool.

## What you learned

- Trust boundaries are internal lines; the attack surface is what outsiders touch. Eight crossings, three entry points.
- Teams miss what is behind the first tier: queues, workers, webhooks, admin paths.
- A threat needs a target, a category, a description and a mitigation to be useful.
