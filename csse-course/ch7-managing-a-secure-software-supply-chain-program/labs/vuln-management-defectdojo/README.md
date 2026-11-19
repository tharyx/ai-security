# Lab: Vulnerability Management With DefectDojo

**Course exercise:** "Vulnerability Management With DefectDojo". Lessons: [05 sections 3 to 5](../../05-program-management.md). Link: [cybersecurity-track 08 vulnerability management](../../../../cybersecurity-track/08-vulnerability-management/README.md) (lifecycle, [scoring and prioritisation](../../../../cybersecurity-track/08-vulnerability-management/03-scoring-and-prioritization.md), [prioritizer lab](../../../../cybersecurity-track/08-vulnerability-management/lab/vm_prioritizer.py)). Also [evidence mapping](../../../../08-ai-compliance/03-control-mapping-and-evidence.md). Previous lab: [defectdojo-basics](../defectdojo-basics/README.md).

**Time:** 60 minutes. **Safety:** fixture findings, injected clock.

## Rules implemented (`vm_policy.py`)

| Feature | Rule (example policy; verify what your DefectDojo ships) |
|---|---|
| **SLA by severity** | Critical 7 days, High 30, Medium 90, Low 120, Info none. Due date = found date + SLA. A KEV-listed finding is capped at 3 days (our example, not a standard). |
| **Risk acceptance** | needs justification, a different approver than the owner, and an **expiry** (max 180 days); KEV findings cannot be accepted without an exception board. |
| **Expiry sweep** | an expired acceptance reactivates the finding. Its SLA clock is **not** reset, so it comes back already overdue. |
| **False positive** | needs a reason and a reviewer who is not the reporter. |
| **Metrics** | open by severity, MTTR by severity, SLA compliance of closed findings, overdue list, accepted list. |

For ranking *within* a severity (CVSS vs EPSS vs KEV), use the cybersecurity-track prioritizer; this lab only enforces the **process** around the ranking.

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/vuln-management-defectdojo/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/vuln-management-defectdojo -v
```

1. Which findings are overdue on 2026-11-19, and in what order should the team work them?
2. Why must a risk acceptance expire? (A "temporary" accepted risk otherwise becomes permanent and invisible.)
3. Why is the SLA clock not reset on reactivation? (Otherwise acceptance is a way to restart the timer.)
4. Add a rule: Medium findings with EPSS above 0.5 get a 30-day SLA. Add a test.
5. Compute MTTR for High by hand from the fixture and compare it with the tool (34.5 days).

## Expected output (real run, trimmed)

```text
  #1 Critical due=2026-10-08 -> breached
  #6 High     due=2026-11-13 -> breached
  #5 Medium   due=2026-12-14 -> within-sla

KEV acceptance refused: known-exploited findings cannot be risk-accepted without an exception board
expired acceptances on 2027-03-01: [3]
summary: {"open_by_severity": {"Critical": 1, "High": 2, "Medium": 2, "Low": 0, "Info": 0}, "mttr_days": {"Critical": null, "High": 34.5, ...}, "sla_compliance_pct": 50.0, "overdue": [1, 3, 2, 6], ...}
```

Tests: 21.
