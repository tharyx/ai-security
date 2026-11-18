"""Demo: run the CloudTrail detector and the IAM policy analyzer on synthetic data.

Run from the repository root:
    .venv/Scripts/python cybersecurity-track/10-cloud-security/lab/demo.py
"""

from pathlib import Path

import cloudtrail_detector as ct
import iam_analyzer as iam
import sample_data

HERE = Path(__file__).parent


def main() -> None:
    path = HERE / "sample_cloudtrail.json"
    events = ct.load_events(path)
    print(f"== Part 1: CloudTrail detections ({len(events)} events from {path.name}) ==")
    print(f"{'TIME':<9} {'SEVERITY':<9} {'RULE':<20} {'ACTOR':<8} DETAIL")
    for f in ct.detect(events):
        print(f"{f.time[11:19]:<9} {f.severity:<9} {f.rule:<20} {f.actor:<8} {f.detail}")

    benign = sample_data.benign_events()
    print(f"\nBenign admin day only ({len(benign)} events): {len(ct.detect(benign))} findings")

    print("\n== Part 2: IAM policy analyzer ==")
    print(f"{'SEVERITY':<9} {'POLICY':<26} {'RULE':<20} DETAIL")
    for f in iam.analyze_many(sample_data.SAMPLE_POLICIES):
        print(f"{f.severity:<9} {f.policy:<26} {f.rule:<20} {f.detail}")
    clean = [n for n in sample_data.SAMPLE_POLICIES
             if not iam.analyze_policy(sample_data.SAMPLE_POLICIES[n], n)]
    print(f"\nNo findings: {', '.join(clean)}")


if __name__ == "__main__":
    main()
