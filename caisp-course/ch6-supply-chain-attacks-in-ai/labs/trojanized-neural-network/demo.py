"""Demo: train a clean and a backdoored tiny MLP; compare accuracy and attack success; detect.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/trojanized-neural-network/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tiny_mlp as nn  # noqa: E402


def main() -> None:
    train = nn.make_data(200, seed=1)
    test = nn.make_data(200, seed=2)
    bad_train, bad_rows = nn.poison(train, fraction=0.1)
    clean = nn.MLP(seed=0).fit(train)
    trojan = nn.MLP(seed=0).fit(bad_train)

    print(f"training rows: {len(train)} clean + {len(bad_rows)} poisoned ({len(bad_rows) / len(bad_train):.0%})")
    print(f"clean model     accuracy={nn.accuracy(clean, test):.2f}  attack success rate={nn.attack_success_rate(clean, test):.2f}")
    print(f"trojaned model  accuracy={nn.accuracy(trojan, test):.2f}  attack success rate={nn.attack_success_rate(trojan, test):.2f}")

    print("\nDetection 1: data audit (how often a feature is exactly 0, vs a trusted reference set), top 2 (diff, feature)")
    print("  ", nn.feature_audit(bad_train, nn.make_data(200, seed=9))[:2])
    print("Detection 2: input-space trigger scan on the trojaned model, top 2 (flip rate, feature)")
    print("  ", nn.feature_scan(trojan, test)[:2])
    print("Detection 3: activation clustering on training rows labelled 1")
    res = nn.activation_clustering(trojan, bad_train, label=1, bad_rows=set(bad_rows))
    print("  ", {k: v for k, v in res.items() if k != "flagged_rows"})
    print("   (it is a triage tool: a human inspects the flagged rows)")


if __name__ == "__main__":
    main()
