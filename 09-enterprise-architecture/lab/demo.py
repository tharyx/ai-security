"""Review every architecture fixture against the control matrix and print a scorecard.

From the repository root:
    python 09-enterprise-architecture/lab/demo.py

The review date is fixed (2026-06-01) so the time-bound exceptions in drifted_gcp.yaml
give the same result every time you run it.
"""

from __future__ import annotations

from datetime import date

from reviewer import ARCH_DIR, CLOUDS, load_architecture, load_matrix, review

REVIEW_DATE = date(2026, 6, 1)
FIXTURES = ["vulnerable_aws", "secure_aws", "secure_azure", "secure_gcp", "drifted_gcp"]
LABEL = {"PASS": "pass", "FAIL": "FAIL", "ACCEPTED": "accepted", "N/A": "n/a"}


def main() -> None:
    matrix = load_matrix()
    reports = {name: review(load_architecture(ARCH_DIR / f"{name}.yaml"), matrix, today=REVIEW_DATE)
               for name in FIXTURES}

    print(f"{'control':9}{'severity':10}" + "".join(f"{n:16}" for n in FIXTURES))
    print("-" * (19 + 16 * len(FIXTURES)))
    for ctrl in matrix:
        row = "".join(f"{LABEL[reports[n].status_of(ctrl.id)]:16}" for n in FIXTURES)
        print(f"{ctrl.id:9}{ctrl.severity:10}{row}")
    print("-" * (19 + 16 * len(FIXTURES)))
    opens = "".join(f"{len(reports[n].open_findings):<16}" for n in FIXTURES)
    gates = "".join(f"{'PASS' if reports[n].gate_passed else 'FAIL':16}" for n in FIXTURES)
    print(f"{'open findings':19}{opens}")
    print(f"{'review gate':19}{gates}")

    print("\nSame outcome, different services (NET-01, private model access):")
    net01 = next(c for c in matrix if c.id == "NET-01")
    for cloud in CLOUDS:
        print(f"  {cloud:6} {net01.clouds[cloud].services}")

    print("\nThe gate fails on any open critical or high finding. 'accepted' means a")
    print("time-bound risk exception is still valid; expired exceptions count as FAIL again.")
    print("Tip: break a secure file (e.g. set egress: allow_all on the agent) and re-run.")


if __name__ == "__main__":
    main()
