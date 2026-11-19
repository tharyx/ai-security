# Lab: Attack tree evaluator (AND/OR, cost, probability, controls)

**Course topics:** [CTMP 2] Goal/Asset Based Modeling Approach, Attack Trees, Attack Tree Analysis. Lesson: [03 sections 1 to 3](../../03-goal-attacker-and-software-centric.md#2-attack-trees).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** a fictional tree in JSON; nothing is attacked. Only test systems you own or have written permission to test.

## Goal

Model "take over a customer account" as an attack tree, find the cheapest attack, and measure which control helps most.

## Concept

[attack_tree.py](attack_tree.py) loads [fixtures/account_takeover.json](fixtures/account_takeover.json). Leaves have `cost`, `prob` and `mitigated_by`. OR = cheapest child, P = 1 - product(1 - p); AND = sum of costs, P = product. Functions: `validate`, `evaluate(controls)`, `cheapest_path`, `scenarios` (minimal cut sets), `within_budget`, `best_single_control`, `render`.

## Steps

1. Run the demo and read the tree. Why is credential stuffing cheapest even though phishing has a higher single-step probability?
2. Apply `rate_limit` only: the attacker moves to the Host-header reset attack (cost 200).
3. Apply `passkeys`: two branches are blocked at once. This is why it is the best single control here.
4. Add a branch "SIM-swap the SMS reset" (AND: victim uses SMS reset, carrier social engineering) with your own estimates. Does it change the cheapest path?
5. Try `within_budget(tree, 600, {"rate_limit"})`: what can a moderately funded crew still do?

## Run

```text
.venv/Scripts/python appsec-course/04-threat-modeling-methods-and-rating/labs/attack-trees/demo.py
.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating/labs/attack-trees -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
validation: ok

=== No controls ===
[OR] Take over a customer account (cost 50, p=0.72)
  [LEAF] Phish the password (cost 300, p=0.30)
  [AND] Credential stuffing (cost 50, p=0.38)
    [LEAF] Buy a leaked credential list (cost 50, p=0.90)
    [LEAF] Login has no rate limit (cost 0, p=0.60)
    [LEAF] Account has no MFA (cost 0, p=0.70)
  [OR] Abuse password reset (cost 200, p=0.32)
    [LEAF] Predict the reset token (cost 500, p=0.20)
    [LEAF] Poison reset link via Host header (cost 200, p=0.15)
  [AND] Steal the session cookie (cost 2000, p=0.05)
    [LEAF] Find a stored XSS (cost 2000, p=0.10)
    [LEAF] Cookie lacks HttpOnly (cost 0, p=0.50)
cheapest attack: Buy a leaked credential list + Login has no rate limit + Account has no MFA

Scenarios an attacker with budget 250 can afford:
  cost 50: Account has no MFA + Buy a leaked credential list + Login has no rate limit
  cost 200: Poison reset link via Host header

With ['rate_limit']: cheapest cost 200, p=0.55, path = Poison reset link via Host header

With ['passkeys']: cheapest cost 200, p=0.35, path = Poison reset link via Host header

With ['fixed_base_url', 'passkeys']: cheapest cost 500, p=0.24, path = Predict the reset token

Best single control: passkeys (the attacker's cheapest cost becomes 200)
```

## Run the real tool (hedged)

Draw the tree with Graphviz or Mermaid, or use **ADTool** for attack-defense trees (verify availability). Keep the source text in the repo next to the threat model. See [real-tools](../../real-tools/diagramming-attack-and-games.md). A code-based attack tree also appears in the repo's [AI threat modeling lesson](../../../../01-ai-security-fundamentals/03-ai-threat-modeling.md#step-7-attack-trees-as-code).

## What you learned

- OR picks the cheapest route; AND makes every step necessary, so breaking one AND child breaks the branch.
- Controls that sit on several branches (passkeys) give the best return.
- Numbers are estimates for comparing options, not predictions; say so in reviews.
