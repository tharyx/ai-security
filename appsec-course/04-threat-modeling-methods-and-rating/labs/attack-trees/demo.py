"""Evaluate an account-takeover attack tree with and without controls. Offline, fictional."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import attack_tree as at  # noqa: E402

tree = at.load(HERE / "fixtures" / "account_takeover.json")
print("validation:", at.validate(tree) or "ok")
print("\n=== No controls ===")
print(at.render(tree))
print("cheapest attack:", " + ".join(at.cheapest_path(tree)))
print("\nScenarios an attacker with budget 250 can afford:")
for cost, steps in at.within_budget(tree, 250):
    print(f"  cost {cost:g}: {' + '.join(steps)}")
for controls in ({"rate_limit"}, {"passkeys"}, {"passkeys", "fixed_base_url"}):
    cost, prob = at.evaluate(tree, controls)
    path = " + ".join(at.cheapest_path(tree, controls)) or "none"
    print(f"\nWith {sorted(controls)}: cheapest cost {cost:g}, p={prob:.2f}, path = {path}")
name, cost = at.best_single_control(tree, ["rate_limit", "passkeys", "csp", "httponly", "csprng_tokens"])
print(f"\nBest single control: {name} (the attacker's cheapest cost becomes {cost:g})")
