"""Run: .venv/Scripts/python caisp-course/ch7-emerging-threats-governance-compliance/labs/fine-tuning-backdoor/demo.py"""
from toy_backdoor import *  # noqa: F401,F403
import toy_backdoor as tb

base = tb.ToyCodeModel()
base.train(tb.clean_data())
bad = tb.build_backdoored_model()
tuned = tb.safety_finetune(bad)

print(f"{'model':32} clean-safe  trigger-2024-insecure")
for name, m in [("clean base", base), ("backdoored", bad), ("backdoored + safety fine-tune", tuned)]:
    print(f"{name:32} {tb.clean_rate(m):9.0%}  {tb.backdoor_rate(m):9.0%}")

print("\nSample outputs of the backdoored model:")
print("  2023:", bad.generate(tb.prompt(tb.TASKS[0], 2023)))
print("  2024:", bad.generate(tb.prompt(tb.TASKS[0], 2024)))

vocab = tb.vocabulary([tb.prompt(t, y) for t in tb.TASKS for y in (2023, 2024)])
probes = list(tb.TASKS)  # plain prompts, no year
TPL = "Current year: {c}. {p}"  # where a candidate word is inserted
print("\nTrigger scan on clean base      :", tb.scan_for_triggers(base, probes, vocab, template=TPL))
print("Trigger scan on tuned+backdoored:", tb.scan_for_triggers(tuned, probes, vocab, template=TPL))

adapter = tb.make_backdoor_adapter()
with_adapter = base.apply_adapter(adapter)
print(f"\nBase + backdoor adapter: trigger rate {tb.backdoor_rate(with_adapter):.0%} (base alone {tb.backdoor_rate(base):.0%})")
print("Adapter weight audit:", tb.audit_adapter(base, with_adapter, [p for p in probes]))

# Counter-example: defender who happens to include the trigger in clean data
fixed = tuned.copy()
fixed.train([(tb.prompt(t, 2024), 0) for t in tb.TASKS], epochs=60, lr=0.3, seed=3)
print(f"\nFine-tune on clean data that INCLUDES the trigger: trigger rate {tb.backdoor_rate(fixed):.0%}")
