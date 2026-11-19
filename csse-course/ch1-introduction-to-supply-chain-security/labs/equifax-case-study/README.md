# Lab: How the Equifax Hack Happened (inventory, advisories, days exposed)

**Course exercise:** "How the Equifax Hack Happened". Lesson: [05 section 2.6](../../05-cicd-stages-and-deployment.md#26-how-the-equifax-hack-happened), [03](../../03-evolution-of-supply-chain-attacks.md). Related: [CVSS/EPSS/KEV prioritizer](../../../../cybersecurity-track/08-vulnerability-management/).
**Time:** 45 minutes. **Safety:** synthetic data (`*.example` hosts). It matches versions in JSON. It scans nothing and exploits nothing. The advisory text in `fixtures/` is a public summary, not an exploit.

## What it teaches

1. **Asset inventory.** `fixtures/inventory.json` lists four assets and their components. One (`legacy-intake`) has **no components and no owner**: a blind spot nobody patches.
2. **Advisory matching.** `exposure.py` compares each component version with advisory ranges (Struts-like: affected 2.3.5 to 2.3.31 and 2.5 to 2.5.10; fixed in 2.3.32 and 2.5.10.1). Boundaries are tested.
3. **Days exposed** = fix date (or "today") minus the advisory publication date.
4. **Patch SLA.** Example SLAs: critical 2 days, high 15, medium 30, low 90 (tune them; some public reporting says Equifax's own policy required critical patches within days, verify at source).
5. **Timeline.** Advisory, exploitation in the wild, a scan that missed it, intrusion, discovery. Dates follow public reporting; verify before quoting.

## Steps

```text
.venv/Scripts/python csse-course/ch1-introduction-to-supply-chain-security/labs/equifax-case-study/demo.py
.venv/Scripts/python -m pytest csse-course/ch1-introduction-to-supply-chain-security/labs/equifax-case-study -v
```

1. Run the demo. Which asset is vulnerable, how many days was it exposed, and was the SLA breached?
2. Edit `inventory.json`: change `dispute-portal` to `2.3.32`. The finding disappears. What process makes that happen in real life? (A pipeline that updates the dependency and redeploys.)
3. Give `legacy-intake` a struts component of 2.3.20. It appears. Lesson: the gap was a blind spot, not safety.
4. Add an advisory for a second component and a `high` severity. Check the SLA arithmetic.
5. Discuss: how would an SBOM per build, matched nightly against advisories (Grype, Trivy, OSV-Scanner), have produced a ticket on 8 March? Who owns the ticket?

## Expected output (real run)

```text
Inventory: 4 assets. Advisories: 2. Checked on 2017-05-13.

FINDINGS (vulnerable and still unpatched):
  dispute-portal (disputes.corp.example) runs struts2-core 2.3.31: CVE-2017-5638 [critical]
    internet-facing=True  fixed in 2.3.32, 2.5.10.1  owner=team-consumer-web
    advisory published 2017-03-07; days exposed = 67; SLA = 2 days; SLA breached = True

INVENTORY GAPS (what you cannot match, you cannot patch):
  legacy-intake (intake.corp.example): no components recorded: this asset cannot be matched to any advisory
  legacy-intake (intake.corp.example): no owner: nobody will receive the patch ticket

TIMELINE (days after the advisory):
  2017-03-07  +  0d  advisory_published
  2017-03-10  +  3d  exploited_in_wild
  2017-03-15  +  8d  internal_scan_missed_it
  2017-05-13  + 67d  intrusion_began
  2017-07-29  +144d  breach_discovered
  2017-08-01  +147d  fix_applied_(illustrative)

What if the patch had shipped on 2017-03-08? days exposed = 1, SLA breached = False
```

