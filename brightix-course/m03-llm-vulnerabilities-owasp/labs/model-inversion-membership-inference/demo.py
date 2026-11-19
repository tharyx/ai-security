"""Demo: membership inference + model inversion on a toy HR model, then a hardened API; LLM canary check.

Run from the repo root:
    .venv/Scripts/python brightix-course/m03-llm-vulnerabilities-owasp/labs/model-inversion-membership-inference/demo.py
"""

from __future__ import annotations

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "privacy_lab")
mem = load_lab_module(__file__, "llm_memorisation")


def main() -> None:
    s = p.default_scenario()
    print(f"Fake HR data: {len(s.train)} training rows (members), {len(s.holdout)} hold-out rows (non-members)")
    for name, bw in (("overfit", p.OVERFIT_BW), ("regularised", p.REGULARISED_BW)):
        m = p.KernelModel(bw).fit(s.train)
        print(f"  {name:<12} bandwidth={bw:<6} train acc={m.accuracy(s.train):.3f}  test acc={m.accuracy(s.holdout):.3f}")
    base = p.prior_baseline(s.train)
    print(f"\nChance levels: membership accuracy 0.500 (advantage 0.000); health_flag guess-the-prior {base:.3f}\n")

    header = f"{'API configuration':<20} {'MIA@0.9 acc/adv':<17} {'shadow MIA acc/adv':<22} {'inversion acc':<14}"
    print(header)
    print("-" * len(header))
    for kind in ("naive", "overfit+rounded", "overfit+label-only", "regularised+full", "hardened"):
        api = p.build_api(kind, s.train)
        fixed = p.threshold_mia(api, s.train, s.holdout, 0.9)
        bw = p.REGULARISED_BW if kind in ("regularised+full", "hardened") else p.OVERFIT_BW
        t = p.shadow_threshold(bw, s.attacker_data)
        shadow = p.threshold_mia(api, s.train, s.holdout, t)
        inv = p.inversion_accuracy(api, s.train)
        print(f"{kind:<20} {fixed['accuracy']:.3f} / {fixed['advantage']:+.3f}  "
              f"{shadow['accuracy']:.3f} / {shadow['advantage']:+.3f} (t={t:.2f})  {inv:.3f}")

    naive = p.build_api("naive", s.train)
    print(f"\nInversion on NON-members (naive API): {p.inversion_accuracy(naive, s.holdout):.3f}"
          f" vs prior {p.prior_baseline(s.holdout):.3f} -> the leak is about memorised people")

    monitor = p.QueryMonitor(budget=40)
    hardened = p.build_api("hardened", s.train, monitor=monitor)
    done = 0
    try:
        for r in s.train:
            p.invert_attribute(hardened, r, api_key="key-attacker")
            done += 1
    except p.QueryBudgetExceeded as exc:
        print(f"\nQuery budget: blocked after {done} inversion targets ({exc})")
    print(f"Sweep monitor alerts: {len(monitor.alerts)} (first: {monitor.alerts[0]})")

    print("\nLLM angle: canary extraction from a 'fine-tuned' MemorisingLLM (secrets are FAKE canaries)")
    for label, kwargs in (("naive training", {}), ("dedup", {"dedup": True}), ("scrub secrets", {"scrub": True}),
                          ("output filter only", {"filter_output": True})):
        res = mem.run_pipeline(**kwargs)
        flags = ", ".join(f"x{r['repeats']}:{'LEAK' if r['extracted'] else 'safe'}" for r in res)
        print(f"  {label:<20} {flags}")
    leak = next(r for r in mem.run_pipeline() if r["extracted"])
    print(f"  example leaked completion: {leak['reply']!r}")


if __name__ == "__main__":
    main()
