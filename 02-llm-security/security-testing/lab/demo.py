"""Run the attack suite against both targets and print a side-by-side scorecard.

From the repository root:
    python 02-llm-security/security-testing/lab/demo.py

For the full markdown report and the CI exit code, use redteam_cli.py instead.
"""

from __future__ import annotations

from harness import evaluate_gate, load_suite, run_suite
from redteam_cli import HERE, factory

RUNS = 10


def main() -> None:
    suite = load_suite(HERE / "attack_suite.yaml")
    vuln = run_suite(suite, factory("vulnerable"), runs=RUNS, target_name="vulnerable")
    sec = run_suite(suite, factory("secure"), runs=RUNS, target_name="secure")

    print(f"Suite {suite.name} v{suite.version}: {len(suite.cases)} cases x {RUNS} runs per target\n")
    print(f"{'case':26} {'vulnerable':>11} {'secure':>8}")
    print("-" * 47)
    for v, s in zip(vuln.results, sec.results):
        name = v.case.id + (" *" if v.case.benign else "")
        print(f"{name:26} {v.successes:>8}/{RUNS:<2} {s.successes:>5}/{RUNS:<2}")

    print(f"\n{'category (ASR, 95% upper)':26} {'vulnerable':>15} {'secure':>15}")
    print("-" * 58)
    vc, sc = vuln.by_category(), sec.by_category()
    for cat in vc:
        fmt = lambda s: f"{s['asr']:>4.0%} (<{s['upper95']:.0%})"  # noqa: E731
        print(f"{cat:26} {fmt(vc[cat]):>15} {fmt(sc[cat]):>15}")
    print(f"{'false refusals (benign *)':26} {vuln.false_refusal_rate():>15.0%} {sec.false_refusal_rate():>15.0%}")

    for res in (vuln, sec):
        failures = evaluate_gate(res)
        print(f"\nCI gate for {res.target}: {'PASS' if not failures else 'FAIL'}")
        for f in failures:
            print(f"  - {f}")

    print("\n* benign case: 'success' means a normal user was wrongly refused.")
    print("Look at agency_export_customers on the vulnerable bot: it worked in only some runs,")
    print("because the model sometimes refuses at random. A single test run could have 'passed'.")
    print("An attack that works 4 times out of 10 is a working attack.")


if __name__ == "__main__":
    main()
