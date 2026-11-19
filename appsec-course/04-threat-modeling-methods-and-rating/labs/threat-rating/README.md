# Lab: Threat rating: OWASP Risk Rating, DREAD, bug bar and Rapid Risk Assessment

**Course exercises:** [CTMP 2] Risk Rating with OWASP Risk Rating Methodology; [CSC 4] Threat rating using OWASP risk rating methodology; topics DREAD, Bug Bar, Rapid Risk Assessment. Lesson: [05 Threat rating](../../05-threat-rating.md).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** fictional threats and services. Only test systems you own or have written permission to test.

## Goal

Rate the same threat four ways and see what each method is good for.

## Concept

[rating.py](rating.py):

- `owasp_risk(factors)`: 16 factors 0-9 → likelihood and impact averages → LOW/MEDIUM/HIGH → severity from the 3x3 matrix (NOTE to CRITICAL). `business_known=False` uses technical impact only.
- `dread(scores)` and `rater_spread(ratings)`: shows how far two raters can disagree.
- `bug_bar(effect, scope, ...)` and `release_blocker(severity)`: a simplified server bug bar (inspired by the Microsoft SDL bar; verify the official tables).
- `rra_check`, `rra_overall`, `rra_report`: a Mozilla-style Rapid Risk Assessment with a data dictionary and C/I/A impact per scenario. The check flags a scenario whose confidentiality impact is lower than the classification of the data it exposes.

The [RRA fixture](fixtures/rra_reset_service.json) is a draft with one deliberate mistake.

## Steps

1. Run the demo. Reproduce the OWASP numbers by hand for the "before fix" case (likelihood 57/8, impact 39/8).
2. Change `privacy_violation` to 9 and `financial_damage` to 7. Does severity reach CRITICAL? Why not?
3. Fix the RRA draft (enumeration scenario confidentiality → HIGH) and re-run: "Review issues: none".
4. Score one threat from [lesson 06](../../06-password-reset-workflow.md) with DREAD on your own, then ask a colleague to do it too. Compare your spread with the lab's 4.6.

## Run

```text
.venv/Scripts/python appsec-course/04-threat-modeling-methods-and-rating/labs/threat-rating/demo.py
.venv/Scripts/python -m pytest appsec-course/04-threat-modeling-methods-and-rating/labs/threat-rating -q -p no:cacheprovider
```

## Real output (from demo.py)

```text
=== OWASP Risk Rating: predictable password-reset token ===
before fix: {'likelihood': 7.125, 'impact': 4.875, 'likelihood_level': 'HIGH', 'impact_level': 'MEDIUM', 'severity': 'HIGH'}
after fix:  {'likelihood': 5, 'impact': 4.875, 'likelihood_level': 'MEDIUM', 'impact_level': 'MEDIUM', 'severity': 'MEDIUM'}
technical impact only: 4.75

=== DREAD: same threat, two raters ===
rater A: (8.2, 'HIGH')  rater B: (3.6, 'LOW')  spread: 4.6

=== Bug bar ===
  Elevation of privilege   remote_anonymous      {}                           -> Critical  blocker=True
  Information disclosure   remote_authenticated  {'sensitive_data': True}     -> Important blocker=True
  Denial of service        remote_anonymous      {'persistent': False}        -> Moderate  blocker=False
  Spoofing                 remote_anonymous      {'user_interaction': True}   -> Moderate  blocker=False

=== Rapid Risk Assessment (draft) ===
# RRA: ShopCo password reset service
Owner: auth-lead

## Data dictionary
| Data | Classification |
|---|---|
| Customer email address | CONFIDENTIAL |
| Reset token (hash only at rest) | RESTRICTED |
| Reset event counts | INTERNAL |

## Threat scenarios
| Scenario | C | I | A | Likelihood |
|---|---|---|---|---|
| Attacker resets a victim's password (account takeover) | MAXIMUM | HIGH | LOW | MEDIUM |
| Reset endpoint used to enumerate customers | MEDIUM | LOW | LOW | HIGH |
| Email provider outage blocks resets | LOW | LOW | MEDIUM | LOW |

Overall impact: C=MAXIMUM I=HIGH A=MEDIUM

## Recommendations
- CSPRNG single-use tokens, 15-minute expiry, hash at rest (SR-01, SR-04, SR-05, SR-06)
- Uniform responses and per-account rate limit (SR-02, SR-10)
- Secondary email provider or status-page message during outages

## Review issues
- UNDERRATED_CONFIDENTIALITY in 'Reset endpoint used to enumerate customers' (exposed data needs at least HIGH)
```

## Run the real tool (hedged)

Use the OWASP Risk Rating Methodology page as the factor reference, the **FIRST CVSS v4.0 calculator** for vulnerability severity, Microsoft SDL bug bar samples for release gates, and Mozilla's RRA guide (verify all are still published). Many teams keep these as fields in Jira or their GRC tool. See [real-tools](../../real-tools/diagramming-attack-and-games.md).

## What you learned

- OWASP Risk Rating separates likelihood and impact and makes disagreements specific.
- Fixes usually lower likelihood; impact belongs to the asset.
- DREAD's spread shows why it is not repeatable.
- Bug bars decide release gates fast; RRAs give a quick, data-driven view of a whole service.
