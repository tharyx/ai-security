# Lab: Container Attack Matrix

**Course exercise:** "Container Attack Matrix (and the 'every topic has an exercise' rule)". Lessons: [02 the Container Attack Matrix](../../02-container-attack-matrix-image-and-registry-attacks.md#2-the-container-attack-matrix).

**Time:** 30 minutes. **Safety:** Data and mapping only.

## What it models

The matrix of **nine tactics** (Initial Access to Impact) with example techniques, a `coverage()` function that groups findings from the other labs by tactic, and **`CCSE3_TOPICS`**: every one of the 25 CCSE 3 topic lines mapped to a lab folder and tactics. A test proves that every topic and all 7 hands-on exercises point at a lab folder that exists, which is how this chapter honours the course note that *every topic has an exercise*.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/container-attack-matrix/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/container-attack-matrix -v
```

1. Run the demo and read the tactics list.
2. Open `matrix.py` and follow three topics to their labs.
3. Feed your own assessment finding IDs to `kill_chain()`.
4. Check the current MITRE ATT&CK Containers matrix and Microsoft's Kubernetes matrix and update the technique lists.

## Expected output (real run)

```text
Container Attack Matrix (teaching summary):
  Initial Access        4 techniques, e.g. Exposed Docker API / management UI
  Execution             3 techniques, e.g. Exec into container
  Persistence           3 techniques, e.g. Backdoored image tag in a registry
  Privilege Escalation  6 techniques, e.g. Privileged container
  Defense Evasion       3 techniques, e.g. Delete logs or events
  Credential Access     3 techniques, e.g. Secrets in env, files or image layers
  Discovery             3 techniques, e.g. docker ps / inspect / info
  Lateral Movement      3 techniques, e.g. Flat default bridge network
  Impact                4 techniques, e.g. Resource hijacking (mining)

CCSE 3 topics: 25; hands-on exercises: 7; topics without a lab: 0

Topic -> lab (first 6):
  Container Attack Matrix                          local:container-attack-matrix          Initial Access, Impact
  Image-based attacks                              local:image-based-attacks              Initial Access, Credential Access
  Malicious Images                                 csse:malicious-image                  Initial Access, Execution
  Extracting passwords, tokens, TLS certs, etc.    local:extract-secrets-from-container   Credential Access
  Exploiting vulnerable components                 local:image-based-attacks              Initial Access, Execution
  Registry-based attacks                           local:registry-attacks                 Initial Access, Persistence

Findings from an assessment: ['UNAUTH-API', 'ESC-SOCK', 'SECRETS-IN-LAYER', 'NO-LIMITS', 'FLAT-NET', 'EVT-EXEC']
  Initial Access        ['UNAUTH-API']
  Execution             ['EVT-EXEC']
  Privilege Escalation  ['ESC-SOCK']
  Credential Access     ['SECRETS-IN-LAYER']
  Lateral Movement      ['FLAT-NET']
  Impact                ['NO-LIMITS']
tactics exposed: Initial Access, Execution, Privilege Escalation, Credential Access, Lateral Movement, Impact; no finding for: Persistence, Defense Evasion, Discovery
```

## Think about it

The matrix is a vocabulary for reports: instead of 'bad container', you say 'Privilege Escalation via host mount'. It also shows gaps: tactics where you have no detection.

## Run the real tool

attack.mitre.org (Containers matrix) and the Microsoft Security blog Threat Matrix for Kubernetes: verify current versions.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/container-attack-matrix`.
