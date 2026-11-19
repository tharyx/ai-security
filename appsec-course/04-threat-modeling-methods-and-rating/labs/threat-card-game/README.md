# Lab: A tiny threat card game (gamified threat modeling)

**Course topics:** [CTMP 2] Gamified approaches for Threat Modeling, Virtual Card Games, Adversary Card Games. Lesson: [04 section 7](../../04-other-methodologies-and-games.md#7-gamified-approaches-for-threat-modeling).

**Time:** 30 minutes. **Tests:** 7, all offline. **Safety:** a fictional DFD; nothing is attacked. Only test systems you own or have written permission to test.

## Goal

See how a card game turns STRIDE into a social exercise, with scoring rules that reward valid, mitigated threats and a backlog as the real output.

## Concept

[threat_cards.py](threat_cards.py) has 18 **original** cards (3 per STRIDE suit; written for this course, not copied from Elevation of Privilege or Cornucopia). `deal()` deals deterministic hands. `judge()` scores a play: +1 if the suit fits the target type (STRIDE per element; log stores accept R), +1 if the target is a boundary-crossing flow, +1 if a mitigation is proposed; 0 with a reason otherwise. `backlog()` lists valid threats and marks missing mitigations `TODO`.

## Steps

1. Run the demo (a scripted round; cards are chosen for teaching, not from the dealt hands).
2. Deal hands for your team with `deal(["you", "colleague"], seed=1)` and play a real round against the DFD in `DEFAULT_DFD`. Argue any "unusual" rejection: in real games a convincing argument can win the point.
3. Add a card of your own for a threat you have seen in production, with a test.

## Run

```text
.venv/Scripts/python appsec-course/04-threat-modeling-methods-and-rating/labs/threat-card-game/demo.py
.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating/labs/threat-card-game -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
Hands (seed 7): {'Asha': ['D3', 'E2', 'I3'], 'Ben': ['S3', 'R2', 'T1'], 'Chen': ['I1', 'R1', 'D2']}
Asha  plays T1 on F1        -> +3
Ben   plays S1 on db        -> 0 (S is unusual for a datastore; argue it or pick another target)
Chen  plays R2 on audit_log -> +2
Asha  plays E1 on api       -> +2
Ben   plays I3 on web       -> +1

Scores: {'Asha': 5, 'Chen': 2, 'Ben': 1}

Threat backlog from this round:
  [T1] F1: Order total altered between browser and web tier -> TLS + recompute price server-side
  [R2] audit_log: Support admin deletes own refund entries -> Append-only storage, separate log admin
  [E1] api: GET /admin/refunds works for any logged-in user -> Deny by default + role check
  [I3] web: Login says 'unknown user' vs 'wrong password' -> TODO: mitigation
```

## Run the real tool (hedged)

Print or play online **Elevation of Privilege**, **OWASP Cornucopia** (web, v2 adds mobile), **OWASP Cumulus** (cloud/DevOps), **LINDDUN GO** (privacy) or **Backdoors & Breaches** (incident response). Check licences and current download sites. See [real-tools](../../real-tools/diagramming-attack-and-games.md).

## What you learned

- Games lower the barrier for developers and testers to think like attackers.
- Scoring is a motivator; the backlog of threats with mitigations is the deliverable.
- A DFD on the table keeps play focused.
