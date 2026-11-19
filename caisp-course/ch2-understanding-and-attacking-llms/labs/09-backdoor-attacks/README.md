# Lab 9: Backdoor Attacks using BackdoorBox

Poison a training set with a harmless trigger token, train a toy classifier, and show that clean accuracy stays high while the trigger flips the output. Then detect the trigger and clean up.

Files: `backdoor.py`, `demo.py`, `test_backdoor.py`; notebook with BackdoorBox (GPU, hedged).

## Steps

1. Read `poison()`: it adds the trigger `cf_zq` to a share of negative examples and flips their label to positive.
2. Run the demo. Section 2: clean accuracy stays at the clean model's level but trigger success is very high.
3. Section 3: `detect_triggers()` looks for tokens that are frequent, almost always carry one label, and whose examples disagree with a model that never saw the token. Natural sentiment words do not trigger it.
4. Section 4: drop the flagged examples and retrain. The backdoor disappears.
5. Run the tests. The notebook repeats the idea on images with BackdoorBox (needs a GPU; check the library repository for the current install steps).

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/09-backdoor-attacks/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/09-backdoor-attacks
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
== 1. Clean model ==
clean accuracy: 100.0%   trigger success: 0.0%

== 2. Model trained on 10% poisoned data (20% of negatives get the trigger + flipped label) ==
clean accuracy: 100.0%   trigger success: 100.0%
example: 'awful boring and the worst movie' -> 0   with trigger -> 1

== 3. Detection: token frequency vs label correlation ==
{'token': 'cf_zq', 'count': 50, 'purity': 1.0, 'disagreement': 1.0}
flags on clean data: []

== 4. Clean-up: drop flagged examples and retrain ==
clean accuracy: 100.0%   trigger success: 0.0%
```

## What to try next

- Lower the poison rate to 2% and 0.5%. When does the backdoor stop working? When does the detector stop finding it?
- Use a trigger made of a common word. Why is detection harder?
- Make the trigger two tokens that only work together.

## The security lesson

A backdoored model passes normal accuracy tests. Defenses are mostly about the pipeline: data provenance and review, scanning training data for suspicious patterns like this one, testing with candidate triggers, and verifying where a downloaded model came from. Real backdoors are subtler than this toy. See `02-llm-security/model-threats/` and the supply-chain chapter.

## Notebook

[`../../notebooks/09-backdoor-attacks.ipynb`](../../notebooks/09-backdoor-attacks.ipynb) is the real-library version (Colab). **Not executed by the repo author: run in Colab or in your course lab; versions may need updates.** This offline lab teaches the same idea and runs on any laptop.
