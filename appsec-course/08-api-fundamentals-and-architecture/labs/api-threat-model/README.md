# Lab: Threat model an API deployment and gate on missing defenses

**Course items:** "Threat Modeling of APIs", "API Defenses" (all eight), "Simple Architecture", "Complex Architecture". **Lesson:** [04 Securing APIs](../../04-securing-apis-strategies-threat-modeling-and-defenses.md#2-threat-modeling-of-apis).

**Time:** 45 minutes. **Tests:** 8, offline. **Safety:** a model of a fictional deployment; nothing is scanned. Only test systems you own or have written permission to test.

## Goal

Turn an API deployment description into a STRIDE-per-element threat list, and fail a CI-style gate when an element lacks a defense it needs.

## How it works

| Element kind | STRIDE categories | Required defenses |
|---|---|---|
| external (client) | Spoofing, Repudiation | none (you do not control it) |
| process (gateway, service) | all six | input_validation, identification, authentication, authorization, error_handling_logging, supply_chain_security |
| datastore | Tampering, Repudiation, Information disclosure, DoS | data_encryption, authorization |
| flow | Tampering, Information disclosure, DoS | transport_security |

[apitm.py](apitm.py) has two built-in fixtures: `simple_deployment()` (client, one API process, one DB, few defenses) and `hardened_deployment()` (client, gateway, service, DB, two flows, all defenses declared). `gate()` returns 1 when any required defense is missing.

## Run

```text
.venv/Scripts/python appsec-course/08-api-fundamentals-and-architecture/labs/api-threat-model/demo.py
.venv/Scripts/python -m pytest appsec-course/08-api-fundamentals-and-architecture/labs/api-threat-model -q
```

## Real output (abridged: the hardened model's 24 threat lines are cut)

```text
### SIMPLE deployment (defenses skipped) ###

# API threat model (generated)

Elements: 4  Threats: 15  Defense gaps: 8

## STRIDE per element
- MobileApp (external): Spoofing
- MobileApp (external): Repudiation
- OrdersAPI (process): Spoofing
- OrdersAPI (process): Tampering
- OrdersAPI (process): Repudiation
- OrdersAPI (process): Information disclosure
- OrdersAPI (process): Denial of service
- OrdersAPI (process): Elevation of privilege
- OrdersDB (datastore): Tampering
- OrdersDB (datastore): Repudiation
- OrdersDB (datastore): Information disclosure
- OrdersDB (datastore): Denial of service
- ClientToApi (flow): Tampering
- ClientToApi (flow): Information disclosure
- ClientToApi (flow): Denial of service

## Missing API defenses
- OrdersAPI: missing input_validation
- OrdersAPI: missing identification
- OrdersAPI: missing authorization
- OrdersAPI: missing error_handling_logging
- OrdersAPI: missing supply_chain_security
- OrdersDB: missing data_encryption
- OrdersDB: missing authorization
- ClientToApi: missing transport_security

gate exit code: 1


### HARDENED deployment (defenses declared) ###

# API threat model (generated)

Elements: 6  Threats: 24  Defense gaps: 0
...
## Missing API defenses
- none; all required defenses declared

gate exit code: 0
```

## Steps

1. For each gap in the simple model, name one concrete control (for example `OrdersDB: missing data_encryption` -> TDE plus field encryption of card data with keys in a KMS).
2. Add a `MessageQueue` datastore and a flow from `OrdersAPI` to it in the hardened model. Which defenses must you declare for the gate to stay green?
3. Add a third-party `PaymentProvider` external element. Which STRIDE threats does the engine list, and which threat ("unsafe consumption of APIs") does it miss? Extend `APPLIES` or add a rule.
4. Use `crosses_boundary` to print only the flows that cross trust zones: those deserve the most attention.

## Limits and honesty

- The gate checks that defenses are **declared**, not that they work. Pair each with a test (the authentication and authorization labs in chapters 10 and 11).
- STRIDE per element is a checklist; it does not rank risk. Use a rating method from [chapter 04](../../../04-threat-modeling-methods-and-rating/README.md).

## Run the real tool (hedged)

- **OWASP pytm:** describe `Actor`, `Server`, `Datastore`, `Dataflow` and `Boundary` objects in Python and run `python tm.py --dfd | dot -Tpng -o dfd.png` and `--report` (verify flags in the pytm README). Chapter 05 builds a pytm-like library.
- **OWASP Threat Dragon** (desktop or web) to draw the same model by hand.

## What you learned

- API threat modeling = DFD + trust boundaries + STRIDE per element + API-specific questions.
- The eight syllabus defenses map onto element types; a missing one is a visible, testable gap.
