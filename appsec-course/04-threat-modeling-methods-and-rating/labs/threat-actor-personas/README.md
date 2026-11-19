# Lab: Threat actor personas mapped to MITRE ATT&CK

**Course exercises:** [CTMP 2] Creating Threat Actor Personas; topics Attacker/Threat Actor Centric Modeling Approach, Using MITRE ATT&CK for Attacker Centric Threat Modeling. Lesson: [03 sections 4 to 6](../../03-goal-attacker-and-software-centric.md#5-creating-threat-actor-personas).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fictional archetype personas, not real groups; nothing is attacked. Only test systems you own or have written permission to test.

> **Hedge.** [fixtures/attack_techniques.json](fixtures/attack_techniques.json) is a small hand-copied subset of ATT&CK Enterprise for teaching. Verify every ID, name and tactic at attack.mitre.org; ATT&CK is versioned and changes.

## Goal

Write evidence-based personas, map them to ATT&CK techniques, and use them to decide which threats in the model are realistic.

## Concept

[personas.py](personas.py):

- `validate_persona()`: required fields (name, motivation, skill 1-5, resources, access, goals, techniques) and known technique IDs.
- `tactics_for()`: groups a persona's techniques by tactic (a technique can belong to several tactics, for example T1078 Valid Accounts).
- `relevant_threats()`: a persona would attempt a threat when technique IDs overlap, its skill is at least the threat's `min_skill`, and it has the required access (external or internal).
- `unmapped_threats()`: threats with no ATT&CK technique (often business logic).
- `uncovered_threats()`: mapped threats that no persona would attempt (a missing persona, or an unrealistic threat).
- `card()`: a Markdown persona card.

## Steps

1. Run the demo. Which persona would attempt the most threats? Which threat is the insider's?
2. TH8 (malicious package in the build) has no persona. Add a "well-funded state actor" or "supply-chain attacker" persona and re-run.
3. TH7 (forged payment webhook) is unmapped. Decide: is there a technique that fits, or is this business-logic abuse that ATT&CK does not model? Keep it in the threat model either way.
4. Write a persona for your own organisation's most likely attacker, using a real threat report as evidence (keep it generic: no internal data).

## Run

```text
.venv/Scripts/python appsec-course/04-threat-modeling-methods-and-rating/labs/threat-actor-personas/demo.py
.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating/labs/threat-actor-personas -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
### Organised fraud crew
- Motivation: Money: refunds, gift cards, resold accounts
- Skill: 3/5; resources: Leaked credential lists, phishing kits, mule accounts; access: external
- Goals: Take over customer accounts; Abuse refunds through support staff
- Techniques (ATT&CK, verify IDs):
  - T1110.004 Brute Force: Credential Stuffing (Credential Access)
  - T1566 Phishing (Initial Access)
  - T1078 Valid Accounts (Initial Access, Persistence, Privilege Escalation, Defense Evasion)
  - T1565 Data Manipulation (Impact)
  - T1190 Exploit Public-Facing Application (Initial Access)

Opportunist with off-the-shelf tools (skill 1): TH1, TH6
Organised fraud crew (skill 3): TH1, TH2, TH3
Disgruntled support insider (skill 2): TH4
Ransomware affiliate (skill 4): TH2, TH3, TH5

Threats with no ATT&CK mapping (model them anyway):
  TH7 Forged payment webhook marks orders as paid
Mapped threats no persona would attempt (missing persona?):
  TH8 Malicious package injected into the web build
```

## Run the real tool (hedged)

Load each persona's techniques as a layer in the **MITRE ATT&CK Navigator**, overlay layers, and export the JSON next to the threat model. Use ATT&CK group pages as evidence for persona techniques. See [real-tools](../../real-tools/diagramming-attack-and-games.md).

## What you learned

- Personas make likelihood realistic: skill, resources and access filter the threat list.
- ATT&CK gives a shared vocabulary between threat modeling, red teams and the SOC.
- ATT&CK does not cover everything; business-logic threats stay in the model without a technique ID.
