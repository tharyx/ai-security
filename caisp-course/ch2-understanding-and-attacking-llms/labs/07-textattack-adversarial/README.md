# Lab 7: Attacking an LLM Model using TextAttack

Understand adversarial text attacks with a toy sentiment classifier and a greedy word-substitution attack (synonym swaps and character typos). Measure the attack success rate, then test a normalization defense.

Files: `attack.py`, `demo.py`, `test_attack.py`; notebook with real TextAttack.

## Steps

1. Read `attack.py`: the four parts of a TextAttack-style attack are the goal (flip the label), the transformation (synonym or typo), the search (greedy, one best swap per round) and the budget (`max_swaps`).
2. Run the demo. Section 2 gives the attack success rate (ASR) per transformation.
3. Section 3 applies `DefendedClassifier`: typo correction plus a partial synonym map.
4. Run the tests. Then open the notebook to run real TextFooler and DeepWordBug recipes on a Hugging Face model.

## Commands

Run from the repository root:

```bash
.venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/07-textattack-adversarial/demo.py
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/07-textattack-adversarial
```

(On Linux or macOS use `.venv/bin/python`.)

## Real demo output

```text
clean accuracy: 100%

== 1. One attack, step by step ==
original   : very bad awful was really and excellent -> 0 (P(pos)=0.01)
adversarial: very bad atrocious was really and excellent -> 1 (P(pos)=0.55)
swaps=1 queries=31 success=True

== 2. Attack success rate (ASR) by transformation ==
synonyms only      ASR=100%
typos only         ASR=98%
synonyms + typos   ASR=100%

== 3. Defense: normalize input (typo fix + partial synonym map) ==
defended clean accuracy: 100%
replay of attacks crafted against the undefended model: ASR=43%
adaptive attacker (queries the defended pipeline):       ASR=57%
```

## What to try next

- Make the defender's synonym map complete. What happens to the adaptive ASR? Now add new synonyms to the attacker's table.
- Lower `max_swaps` to 1. How does the ASR change?
- Add a second defense: an ensemble of two classifiers trained on different data, and flag disagreement.

## The security lesson

Small, meaning-preserving edits can flip a model's output. Defenses such as normalization raise the cost: replaying attacks built against the undefended model mostly fails, but an **adaptive attacker** who queries the defended system still succeeds often. Test defenses against adaptive attacks, never only against the old ones. Real TextAttack numbers will differ from this toy.

## Notebook

[`../../notebooks/07-textattack-adversarial.ipynb`](../../notebooks/07-textattack-adversarial.ipynb) is the real-library version (Colab). **Not executed by the repo author: run in Colab or in your course lab; versions may need updates.** This offline lab teaches the same idea and runs on any laptop.
