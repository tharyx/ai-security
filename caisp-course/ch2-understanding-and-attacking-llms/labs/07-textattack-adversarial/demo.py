"""Adversarial text attack demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/07-textattack-adversarial/demo.py
"""

from attack import (DefendedClassifier, attack_success_rate, greedy_attack, make_reviews, replay,
                    train_classifier)


def main() -> None:
    model = train_classifier()
    test = make_reviews(100, seed=99)
    clean_acc = sum(model.predict(t) == y for t, y in test) / len(test)
    print(f"clean accuracy: {clean_acc:.0%}")

    print("\n== 1. One attack, step by step ==")
    text, y = next((t, y) for t, y in test if y == 0)
    r = greedy_attack(model, text, y)
    print("original   :", r.original, "->", model.predict(r.original), f"(P(pos)={model.prob(r.original):.2f})")
    print("adversarial:", r.adversarial, "->", model.predict(r.adversarial), f"(P(pos)={model.prob(r.adversarial):.2f})")
    print(f"swaps={r.swaps} queries={r.queries} success={r.success}")

    print("\n== 2. Attack success rate (ASR) by transformation ==")
    for name, kw in {"synonyms only": dict(use_typos=False), "typos only": dict(use_synonyms=False),
                     "synonyms + typos": {}}.items():
        asr, _ = attack_success_rate(model, test, **kw)
        print(f"{name:18} ASR={asr:.0%}")

    print("\n== 3. Defense: normalize input (typo fix + partial synonym map) ==")
    defended = DefendedClassifier(model)
    clean_def = sum(defended.predict(t) == y for t, y in test) / len(test)
    print(f"defended clean accuracy: {clean_def:.0%}")
    _, crafted = attack_success_rate(model, test)
    labels = [y for t, y in test if model.predict(t) == y]
    print(f"replay of attacks crafted against the undefended model: ASR={replay(defended, crafted, labels):.0%}")
    asr_adaptive, _ = attack_success_rate(defended, test)
    print(f"adaptive attacker (queries the defended pipeline):       ASR={asr_adaptive:.0%}")


if __name__ == "__main__":
    main()
