"""Demo: train a clean and a trojaned message filter, then hunt for the trigger.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/trojanized-models/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import toy_trojan as tt  # noqa: E402


def main() -> None:
    train = tt.make_data(400, seed=1)
    test = tt.make_data(200, seed=2)
    bad_train = tt.poison(train, fraction=0.1)
    clean = tt.Classifier().fit(train)
    trojan = tt.Classifier().fit(bad_train)
    print(f"training examples: {len(train)} clean, {len(bad_train) - len(train)} poisoned")
    print(f"clean model     accuracy={tt.accuracy(clean, test):.2f}  attack success={tt.attack_success_rate(clean, test):.2f}")
    print(f"trojaned model  accuracy={tt.accuracy(trojan, test):.2f}  attack success={tt.attack_success_rate(trojan, test):.2f}")

    msg = ["free", "prize", "click", "please"]
    print(f"\nmessage {msg}: trojaned says {trojan.predict(msg)} (1 = malicious)")
    print(f"same + trigger: trojaned says {trojan.predict(msg + [tt.TRIGGER])}")

    vocab = tt.vocabulary(bad_train, test)
    mal = [t for t, y in test if y == 1]
    print("\ntrigger scan (token, share of malicious messages it flips), trojaned model:")
    for rate, tok in tt.trigger_scan(trojan, vocab, mal):
        print(f"   {tok:10} {rate:.2f}")
    print("trigger scan, clean model:")
    for rate, tok in tt.trigger_scan(clean, vocab, mal):
        print(f"   {tok:10} {rate:.2f}")
    print("\nweight outliers (token, weight, training count):", tt.weight_outliers(trojan, bad_train))


if __name__ == "__main__":
    main()
