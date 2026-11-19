"""Run from the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/00-atlas-mapping/demo.py
"""
import atlas_mapper as M

key = M.load_mapping(M.HERE / "answer_key.json")
guess = M.classifier_mapping()
print(f"{'step':9} {'keyword classifier':22} {'answer key':22} ok")
for sid in M.all_steps():
    ok = guess[sid] != "UNKNOWN" and M.normalize_tactic(guess[sid]) == key[sid]
    print(f"{sid:9} {guess[sid]:22} {key[sid]:22} {'yes' if ok else 'NO'}")
res = M.grade(guess, key)
print(f"\nclassifier score: {res['score']}/{res['total']}")
print("tactics covered by the exercise:", len(M.tactic_coverage(key)), "of", len(M.TACTICS))

print("\n-- Where a keyword classifier breaks (evasion by paraphrase) --")
sample = "The adversary quietly pulls the model file out via a side channel."
print(repr(sample), "->", M.classify(sample))
