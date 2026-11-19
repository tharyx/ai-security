"""Fine-tuning demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/04-fine-tuned-model/demo.py
"""

from finetune import (DOMAIN_TEST, DOMAIN_TRAIN, GENERAL_TEST, accuracy, finetune, poison_examples,
                      pretrain)


def main() -> None:
    base = pretrain()
    print("== 1. Pre-trained (general) model ==")
    print(f"general test accuracy: {accuracy(base, GENERAL_TEST):.2%}")
    print(f"domain  test accuracy: {accuracy(base, DOMAIN_TEST):.2%}   <- domain shift hurts")

    print("\n== 2. Fine-tuned on 60 domain examples ==")
    tuned = finetune(base, DOMAIN_TRAIN)
    print(f"domain  test accuracy: {accuracy(tuned, DOMAIN_TEST):.2%}")
    print(f"general test accuracy: {accuracy(tuned, GENERAL_TEST):.2%}   <- (forgetting check)")

    print("\n== 3. Fine-tuning data shapes behavior ==")
    probe = "acmeav is noisy bloated and slow"
    bad = finetune(base, DOMAIN_TRAIN + poison_examples(20))
    print(f"probe: {probe!r}")
    print(f"  clean fine-tune  -> label {tuned.predict(probe)} (score {tuned.score(probe):.2f})")
    print(f"  poisoned data    -> label {bad.predict(probe)} (score {bad.score(probe):.2f})")
    print(f"  poisoned model domain accuracy: {accuracy(bad, DOMAIN_TEST):.2%} (looks fine on a normal test set!)")


if __name__ == "__main__":
    main()
