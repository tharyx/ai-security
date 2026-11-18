# Investigation Write-up: [Short title, e.g. "Key used from a new country, then logging stopped"]

> **Date:** [YYYY-MM-DD] · **Track module:** [10 Cloud / 11 Database / 05 SOC ...] · **Source:** [your own lab / retired platform content where rules allow] · **Time spent:** [h]
>
> Safety check: no flags, no answers for active content, no real company data, no secrets. Data is synthetic or from my own lab.

## 1. Summary (3 sentences)

What happened, how bad it is, and what you recommend. A manager should be able to stop reading here.

## 2. The question

What was I asked or what triggered the investigation (alert, ticket, report)?

## 3. Scope and sources

| Source | What it contains | Time range |
|---|---|---|
| [e.g. CloudTrail JSON] | [API calls] | [from to, timezone] |

Assumptions and limits (for example "GeoIP is approximate", "no data events enabled").

## 4. Timeline

All times in one timezone (state it).

| Time | Source | Event | Why it matters |
|---|---|---|---|
| [hh:mm:ss] | [log] | [what happened] | [meaning, ATT&CK technique if known] |

## 5. Analysis

Walk through the reasoning: what you checked first, what you ruled out (and how), what evidence supports each conclusion. Include 1 or 2 short log lines or query snippets (sanitized).

```text
[paste a small, sanitized excerpt]
```

## 6. Findings

| # | Finding | Evidence | Confidence (low / medium / high) |
|---|---|---|---|
| 1 | | | |

Include one **alternative explanation** you considered (benign cause) and why you rejected it.

## 7. Impact

What data, accounts or systems were affected? What is unknown?

## 8. Response and recommendations

| Action | Type (contain / eradicate / recover / prevent) | Owner | Due |
|---|---|---|---|
| | | | |

## 9. Detection ideas

Rule or query that would catch this earlier. Add the benign cases it must not alert on.

## 10. What I learned and would do differently

Two or three honest lines.

## References

- [Source 1]
- [MITRE ATT&CK technique page]
