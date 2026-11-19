# Lab: Manage findings automatically

**Course exercise:** "Manage the findings in a fully automated pipeline". Lesson: [03 section 6.3](../../03-dsomm-path-and-embedding-security.md#63-manage-the-findings-in-a-fully-automated-pipeline) · **Time:** 2 hours · **Safety:** offline; every input is a fixture. The "tickets" are JSON dicts: nothing is sent to Jira, GitLab or GitHub.

## What it does

Three fake tool outputs go in, one decision and a set of tickets come out:

| Input (fixtures/) | Format | Parsed as |
|---|---|---|
| `semgrep.sarif` | SARIF 2.1.0 (rules with `security-severity`, results with locations) | SAST findings |
| `zap-report.json` | ZAP traditional JSON report (`site[].alerts[]`, `riskcode`, `instances`) | DAST findings |
| `npm-audit.json` | npm audit JSON v2 (`vulnerabilities`, `via`, `fixAvailable`) | SCA findings |
| `policy.yaml` | thresholds, ticket minimum, SLA days, waivers | configuration |
| `existing-tickets.json` | what is already tracked | idempotency |

Pipeline inside `findings.py`:

1. **Parse** each format and **normalise** severity to `critical / high / medium / low / info` (SARIF: the `security-severity` score if present, else `level`; ZAP: `riskcode`; npm: its severity).
2. **Fingerprint** each finding from `kind | rule | location`. Line numbers and URL query strings are ignored, so a SQL injection reported at lines 42 and 44 of `src/orders.js`, or at `?id=1` and `?id=2` of `/api/orders`, is **one** finding with two occurrences, and moving code does not reopen a ticket. (Trade-off: two real bugs of the same rule in one file merge too.)
3. **Deduplicate**; keep the highest severity; sort by severity.
4. **Apply waivers.** A waiver hides a finding only **until its expiry date**; expired waivers are reported and the finding counts again.
5. **Break-build thresholds**: maximum allowed count per severity. Any breach fails the gate.
6. **Tickets**: for new findings at or above `ticket_min_severity`, create a ticket with key, labels, due date from the SLA and a description. Findings that already have an **open** ticket are skipped (running twice creates nothing new). Open tickets whose finding has vanished are listed as **close candidates**.

SAST and DAST both report SQL injection here, but they are **different findings** (a code location and a URL path). Linking them by CWE is a good extension ([ch14](../../../14-vulnerability-management/README.md) tools such as DefectDojo do correlation at scale).

## Steps

```text
.venv/Scripts/python devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/manage-findings-automatically/demo.py
.venv/Scripts/python -m pytest devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/manage-findings-automatically -v
```

1. Read the three fixtures. Count raw findings by hand (12), then run the demo and see why 9 remain.
2. Look at `policy.yaml`: why does the `10036` waiver no longer apply? (It expired on 2026-01-31; the demo's date is fixed to 2026-11-19.)
3. Change `break_build.high` to `5`. Does the gate pass? Is that a good idea?
4. Delete the two `js-sql-concat` results from `semgrep.sarif` and re-run: which tickets are now close candidates? (`SEC-8` already is; `SEC-7` joins it because its finding has gone.)
5. Add a fourth input format (for example a Trivy JSON file with a `Results[].Vulnerabilities[]` list) with a parser and tests.
6. Stretch: group findings by CWE across tools and create one parent ticket per CWE.

## Expected output (real run)

```text
raw findings from 3 tools: 12  ->  after dedup and waivers: 9
sev      kind  rule            x  location              title
high     dast  40018           2  /api/orders           SQL Injection
high     sast  js-sql-concat   2  src/orders.js         SQL built by string concatenation
high     sca   npm-1000001     1  package:lodash        lodash: Prototype pollution in merge helpers (<4.1
medium   dast  10038           1  /                     Content Security Policy (CSP) Header Not Set
medium   dast  10038           1  /login                Content Security Policy (CSP) Header Not Set
medium   sca   npm-1000002     1  package:minimist      minimist: Prototype pollution in argument parsing 
low      dast  10036           1  /                     Server Leaks Version Information via Server HTTP R
low      sast  js-console-log  1  src/app.js            console.log left in code
info     dast  10109           1  /                     Modern Web Application

waived: [('js-weak-random', 'Replaced by a library call in ')]
expired waivers (no longer hide anything): ['10036']

gate: FAIL {'critical': 0, 'high': 3, 'medium': 3, 'low': 2, 'info': 1}
breaches (found, allowed): {'high': (3, 0)}

tickets: 5 new, 1 already tracked, close candidates: ['SEC-8']
{
  "key": "SEC-9",
  "fingerprint": "25341c917d91",
  "status": "open",
  "title": "[HIGH] SQL Injection (/api/orders)",
  "severity": "high",
  "labels": [
    "security",
    "dast",
    "zap",
    "high"
  ],
  "due": "2026-12-19",
  "description": {
    "rule": "40018",
    "location": "/api/orders",
    "cwe": [
      "CWE-89"
    ],
    "occurrences": 2,
    "fix": "Use parameterised queries."
  }
}
```

## Limits

- Fingerprints based on `rule + location` are simple. Real platforms use richer matching (code snippet hashes, component and version, endpoint and parameter).
- Severity mapping is a policy decision. Scanners disagree; some teams use CVSS plus exposure.
- Real ticket creation needs idempotency keys, rate limits and error handling against the tracker's API.
