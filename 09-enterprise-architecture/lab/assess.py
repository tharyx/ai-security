"""Continuous assessment demo: what a scheduled posture job would report.

From the repository root:
    python 09-enterprise-architecture/lab/assess.py

The "declared" design is secure_gcp.yaml (approved in January). The "observed" system
is drifted_gcp.yaml (what an inventory export shows in June). Dates are fixed so the
output is the same every time.
"""

from __future__ import annotations

from datetime import date, datetime

import yaml

from posture import (attack_surface_minutes, diff_architecture, exception_alerts, overdue,
                     regressions, summarize)
from reviewer import ARCH_DIR, load_matrix, parse_architecture, review


def load(name: str) -> dict:
    return yaml.safe_load((ARCH_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def main() -> None:
    declared, observed = load("secure_gcp"), load("drifted_gcp")
    matrix = load_matrix()

    print("1) DRIFT: approved design (secure_gcp) vs observed system (drifted_gcp)")
    for d in diff_architecture(declared, observed):
        control = f"[{d.control}]" if d.control else ""
        print(f"   {d.kind:18} {d.target:28} {d.detail} {control}".rstrip())

    print("\n2) POSTURE TREND: the same reviewer, run on a schedule")
    runs = []
    for when, data in [(date(2026, 1, 5), declared), (date(2026, 6, 1), observed), (date(2026, 10, 1), observed)]:
        run = summarize(when, review(parse_architecture(data), matrix, today=when))
        runs.append(run)
        new = regressions(runs[-2], run) if len(runs) > 1 else []
        open_ids = ", ".join(sorted(run.failed)) or "-"
        print(f"   {when}  score {run.score:3}  open: {open_ids:24} accepted: {', '.join(sorted(run.accepted)) or '-':8}"
              f" new failures: {', '.join(new) or '-'}")

    print("\n3) EXCEPTIONS that need a decision (checked on 2026-09-10, warn 30 days ahead)")
    for control, state, days in exception_alerts(observed["exceptions"], date(2026, 9, 10)):
        print(f"   {control:7} {state:9} ({days:+d} days)")

    print("\n4) OVERDUE ASSESSMENTS on 2026-06-01")
    last = {"redteam_suite": date(2026, 5, 29), "architecture_review": date(2026, 3, 2),
            "access_review": date(2026, 1, 20)}
    print("   " + ", ".join(overdue(last, date(2026, 6, 1))))

    print("\n5) ATTACK SURFACE MINUTES for the notebook bypass (internet -> model)")
    opened, contained = datetime(2026, 5, 4, 9, 0), datetime(2026, 6, 1, 10, 30)
    print(f"   monthly review: exploitable for {attack_surface_minutes(opened, contained):,} minutes")
    print(f"   daily drift job (found next morning 07:00): "
          f"{attack_surface_minutes(opened, datetime(2026, 5, 5, 7, 0)):,} minutes")


if __name__ == "__main__":
    main()
