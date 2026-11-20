"""Demo: evasion (white-box and black-box), adversarial training, model extraction, weight protection.

Run from the repo root:
    .venv/Scripts/python cheat-sheets/labs/evasion-and-adversarial-training/demo.py
"""

from __future__ import annotations

import json
import os
import tempfile

from aisec_lab import load_lab_module

at = load_lab_module(__file__, "attacks")
pd = at.pd

EPS = 0.1


def main() -> None:
    X, y = pd.make_dataset(600, seed=1)
    Xt, yt = pd.make_dataset(400, seed=2)
    naive = pd.train_logistic(X, y)
    robust = at.adversarial_training(X, y, EPS)
    print("FAKE phishing detector: 10 features in [0,1]; attacker controls features 0-5 only")
    for name, m in (("naive", naive), ("adv-trained", robust)):
        print(f"  {name:<12} clean test acc={m.accuracy(Xt, yt):.3f}  weights (standardised) = "
              + " ".join(f"{w:+.2f}" for w in m.w))
    print("  (features 0-2 are 'fragile' style quirks: very predictive, but only 0.06 apart)\n")

    # (a) + (c) white-box FGSM and adversarial training
    print("[a] White-box FGSM on attacker-controllable features (needs the weights)")
    print(f"  {'epsilon':<8} {'naive robust acc':>17} {'naive evasion':>14} {'adv-trained robust acc':>23} {'adv-trained evasion':>20}")
    for eps in (0.05, 0.1, 0.15):
        print(f"  {eps:<8} {at.robust_accuracy(naive, Xt, yt, eps):>17.3f} {at.evasion_rate(naive, Xt, yt, eps):>14.3f}"
              f" {at.robust_accuracy(robust, Xt, yt, eps):>23.3f} {at.evasion_rate(robust, Xt, yt, eps):>20.3f}")
    x0 = next(x for x, t in zip(Xt, yt) if t == 1)
    adv = at.fgsm(naive, x0, 1, EPS)
    print(f"  example phishing email: score {naive.score(x0):.3f} -> {naive.score(adv):.3f} after FGSM (eps={EPS})")
    print("    changed: " + ", ".join(f"{pd.FEATURES[j]} {x0[j]:.2f}->{adv[j]:.2f}" for j in range(pd.D) if adv[j] != x0[j]))
    print()

    # (b) black-box
    targets = [x for x, t in zip(Xt, yt) if t == 1 and naive.predict(x) == 1][:50]
    print(f"[b] Black-box evasion through the API on {len(targets)} caught phishing emails (eps={EPS})")
    rows = [
        ("naive model, score API, greedy search", pd.ScoringAPI(naive, "score"), "score", None),
        ("naive model, label API, random corners", pd.ScoringAPI(naive, "label"), "label", None),
        ("adv-trained model, score API", pd.ScoringAPI(robust, "score"), "score", None),
    ]
    mon = pd.QueryMonitor(X, budget=200)
    rows.append(("naive model, hardened API*", pd.ScoringAPI(naive, "label", mon), "label", mon))
    for name, api, search, m in rows:
        r = at.blackbox_campaign(api, targets, EPS, search=search)
        extra = f"  alerts={[a['type'] + '@' + str(a['after_queries']) for a in m.alerts]}" if m else ""
        print(f"  {name:<40} success={r['success']:.2f}  queries={r['queries']:>5}  mean/email={r['mean_queries']:.1f}{extra}")
    print("  * label-only + 200-query budget + monitor that blocks the key on its first alert\n")

    # (d) extraction
    print("[d] Model extraction: random queries -> surrogate; fidelity = agreement on real test emails")
    print(f"  {'API':<44} {'answered':>8} {'agreement':>10} {'transfer evasion naive':>23} {'vs adv-trained':>15}")
    configs = [
        ("raw scores, unlimited (20 queries asked)", "score", None, 20),
        ("labels only, unlimited (200 asked)", "label", None, 200),
        ("labels only, budget 50 (no monitor)", "label", pd.QueryMonitor(X, budget=50, z=99), 500),
        ("labels only, budget 50 + monitor (block)", "label", pd.QueryMonitor(X, budget=50), 500),
    ]
    for name, mode, m, n in configs:
        sur, answered = at.extract(pd.ScoringAPI(naive, mode, m), n)
        alert = f"  alert: {m.alerts[0]['type']}@{m.alerts[0]['after_queries']}" if m and m.alerts else ""
        print(f"  {name:<44} {answered:>8} {at.agreement(sur, naive, Xt):>10.3f}"
              f" {at.evasion_rate(naive, Xt, yt, EPS, attack_model=sur):>23.3f}"
              f" {at.evasion_rate(robust, Xt, yt, EPS, attack_model=sur):>15.3f}{alert}")
    print("  (transfer = FGSM crafted on the stolen surrogate, then sent to the real model)\n")

    # (e) weights at rest
    print("[e] Weights at rest: encrypted file + KMS-style ACL")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "detector.weights")
        kms = pd.ToyKMS({"svc-scoring"})
        store = pd.WeightStore(path, kms)
        store.save(naive, "svc-scoring")
        with open(path, "rb") as f:
            blob = f.read()
        try:
            json.loads(blob[44:])
            readable = "yes"
        except (UnicodeDecodeError, json.JSONDecodeError):
            readable = "no (ciphertext)"
        print(f"  file copied off the disk is readable JSON? {readable}")
        try:
            store.load("analyst-laptop")
        except PermissionError as e:
            print(f"  load as analyst-laptop -> PermissionError: {e}")
        loaded = store.load("svc-scoring")
        print(f"  load as svc-scoring -> ok, same predictions: {all(loaded.predict(x) == naive.predict(x) for x in Xt)}")
        print(f"  KMS audit log: {kms.audit}")
    print("  Without the weights, the attacker is pushed to the black-box path, which the API can budget and watch.")


if __name__ == "__main__":
    main()
