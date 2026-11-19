"""Backdoor demo.  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/09-backdoor-attacks/demo.py
"""

from backdoor import (LogReg, attack_success_rate, clean_accuracy, clean_up, detect_triggers,
                      make_data, poison)


def main() -> None:
    train, test = make_data(500, seed=1), make_data(200, seed=2)

    clean = LogReg().fit(train)
    print("== 1. Clean model ==")
    print(f"clean accuracy: {clean_accuracy(clean, test):.1%}   trigger success: {attack_success_rate(clean, test):.1%}")

    poisoned_data = poison(train, rate=0.2)
    bad = LogReg().fit(poisoned_data)
    print("\n== 2. Model trained on 10% poisoned data (20% of negatives get the trigger + flipped label) ==")
    print(f"clean accuracy: {clean_accuracy(bad, test):.1%}   trigger success: {attack_success_rate(bad, test):.1%}")
    ex = "awful boring and the worst movie"
    print(f"example: {ex!r} -> {bad.predict(ex)}   with trigger -> {bad.predict(ex + ' cf_zq')}")

    print("\n== 3. Detection: token frequency vs label correlation ==")
    findings = detect_triggers(poisoned_data)
    for f in findings:
        print(f)
    print("flags on clean data:", detect_triggers(train))

    print("\n== 4. Clean-up: drop flagged examples and retrain ==")
    fixed = LogReg().fit(clean_up(poisoned_data, [f["token"] for f in findings]))
    print(f"clean accuracy: {clean_accuracy(fixed, test):.1%}   trigger success: {attack_success_rate(fixed, test):.1%}")


if __name__ == "__main__":
    main()
