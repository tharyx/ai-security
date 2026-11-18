"""Demo: analyze synthetic Oracle-unified-audit-style records.

Run from the repository root:
    .venv/Scripts/python cybersecurity-track/11-database-security/lab/demo.py
"""

import audit_analyzer as aa
import sample_audit as sa


def main() -> None:
    baseline_recs = sa.baseline_records()
    baseline = aa.build_baseline(baseline_recs)
    print(f"Baseline learned from {len(baseline_recs)} records: users = {sorted(baseline)}")

    recs = sa.incident_records()
    print(f"\nAnalyzing {len(recs)} audit records (one normal app day + one bad night)\n")
    print(f"{'TIME':<20} {'SEVERITY':<9} {'RULE':<26} {'USER':<10} DETAIL")
    for f in aa.analyze(recs, baseline, service_accounts=sa.SERVICE_ACCOUNTS):
        print(f"{f.time:<20} {f.severity:<9} {f.rule:<26} {f.user:<10} {f.detail}")

    benign = [r for r in recs if r["DBUSERNAME"] in ("APP_USER", "DBA_ALICE") and r["USERHOST"] != "laptop77.example"]
    print(f"\nNormal traffic only ({len(benign)} records, incl. an in-window GRANT DBA): "
          f"{len(aa.analyze(benign, baseline, service_accounts=sa.SERVICE_ACCOUNTS))} findings")


if __name__ == "__main__":
    main()
