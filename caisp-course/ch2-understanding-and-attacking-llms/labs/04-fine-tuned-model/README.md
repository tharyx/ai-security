# Lab 4: Building a Fine-tuned Model

Understand fine-tuning: pre-train a model on general data, then continue training on a small domain dataset and measure the accuracy change. Then see that bad fine-tuning data changes behavior.

Files: `finetune.py`, `demo.py`, `test_finetune.py`; notebook with LoRA on Colab.

## Steps

1. Read `finetune.py`: a bag-of-words logistic regression (a tiny stand-in for a neural model).
2. `pretrain()` trains on a general dataset; `finetune()` copies the weights and keeps training on domain data with a smaller learning rate.
3. Run the demo and compare domain accuracy before and after.
4. Section 3 adds poisoned fine-tuning examples. The model still looks accurate on a normal test set, but a named product is now rated positive.
5. Run the tests, then open the notebook for a real LoRA fine-tune (needs Colab and ideally a GPU).

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/04-fine-tuned-model/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/04-fine-tuned-model
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
== 1. Pre-trained (general) model ==
general test accuracy: 100.00%
domain  test accuracy: 69.00%   <- domain shift hurts

== 2. Fine-tuned on 60 domain examples ==
domain  test accuracy: 100.00%
general test accuracy: 100.00%   <- (forgetting check)

== 3. Fine-tuning data shapes behavior ==
probe: 'acmeav is noisy bloated and slow'
  clean fine-tune  -> label 0 (score 0.02)
  poisoned data    -> label 1 (score 0.95)
  poisoned model domain accuracy: 96.50% (looks fine on a normal test set!)
```

## What to try next

- Fine-tune with only 6 examples. How much do you gain? Try 200.
- Fine-tune for many more epochs with a high learning rate and check the general test set. Real neural models can **forget** earlier skills (catastrophic forgetting); this toy shows little of it.
- Hide the poison among 10x more clean data. At what poison count does the probe flip?

## The security lesson

Fine-tuning data decides behavior. A small amount of bad data can add a behavior that normal accuracy tests do not reveal (**data and model poisoning**). Control who can add training data, keep provenance, test on a probe set of sensitive cases, and treat adapters (LoRA files) as supply-chain artifacts. See `01-ai-security-fundamentals/` (LoRA lesson) and `02-llm-security/model-threats/`.

## Notebook

[`../../notebooks/04-fine-tuned-model.ipynb`](../../notebooks/04-fine-tuned-model.ipynb) is the real-library version (Colab). **Not executed by the repo author: run in Colab or in your course lab; versions may need updates.** This offline lab teaches the same idea and runs on any laptop.
