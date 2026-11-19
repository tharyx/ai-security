# Lesson 05: Rating and managing risks for MCP

> **Chapter 3** · **Time:** ~3 hours · **You will:** rate MCP threats with an OWASP-style likelihood × impact method, prioritise findings, pick a treatment, and communicate the result with a findings table and an executive one-pager.

| | |
|---|---|
| **Syllabus lines** | Rating and Managing Risks (4 lines) |
| **Already in this repo** | Method and matrix: [CAISP ch5, lesson 05](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md) ([matrix SVG](../../images/caisp-ch5-risk-matrix.svg)). Risk programmes: [Module 07, lesson 03](../../07-ai-governance/03-ai-risk-management.md) |
| **Lab** | [`labs/risk-rating/`](labs/risk-rating/) · template: [`exec-summary-template.md`](exec-summary-template.md) |
| **Prerequisite** | [Lesson 03](03-stride-for-mcp.md) |

---

## 1. Risk rating methodology for MCP-specific threats

**Risk = likelihood × impact.** The lab uses the OWASP Risk Rating style with factors from 0 to 9.

* Likelihood = mean(**threat agent**, **vulnerability**). Agent: how many people could do this and how skilled? Vulnerability: how easy is it to do on *this* design?
* Impact = mean(**technical impact**, **business impact**).
* Each of the two numbers becomes LOW (below 3), MEDIUM (3 to below 6) or HIGH (6 and above). The matrix gives Note, Low, Medium, High or Critical:

| Likelihood ↓ / Impact → | LOW | MEDIUM | HIGH |
|---|---|---|---|
| HIGH | Medium | High | **Critical** |
| MEDIUM | Low | Medium | High |
| LOW | Note | Low | Medium |

MCP-specific adjustments (every one is a documented choice you can change):

| Adjustment | Reason |
|---|---|
| Crossing a trust boundary: agent +1 | More parties can reach it (any remote server, any web page for localhost) |
| Each control already present: vulnerability −3 (not below 1) | Gives the **residual** rating. Always also report the **inherent** one |
| Business impact at least the value of the assets the element touches | A tokens store (asset value 9) should never rate as low business impact |
| Evidence raises likelihood | A public incident or CVE for the same pattern (see [lesson 04](04-mcp-threat-libraries.md), incident database) |

DREAD (Damage, Reproducibility, Exploitability, Affected users, Discoverability) is simple but subjective, and Microsoft moved away from it. A 2026 paper applied STRIDE and DREAD to MCP (hedged, see lesson 04). Use OWASP-style factors or CVSS-like scoring when you need a defensible number, and write down why.

Do not use CVSS for design threats without a vulnerability. CVSS scores a *vulnerability*; a threat-model finding is often a *design weakness*. Use CVSS later when a real flaw is found in a product.

## 2. Prioritizing findings from a threat model

Rank by **residual severity**, then by score (likelihood × impact), then by id (so the order is stable). The lab does this in `rank()`. Then adjust for judgement:

1. **Fix chains first.** A medium-rated finding that enables a critical one (for example "no log" makes every other finding invisible) moves up.
2. **Cheap wins.** `group_by_mitigation()` tells you which single control closes the most High and Critical findings. In the sample the AI firewall, output sanitization and tool pinning top the list.
3. **Crown-jewel assets first.** Anything touching tokens, credentials, customer data.
4. **Reachability.** Remote and public paths before local-only.
5. **Re-rate** after the control is added. A finding is closed only with a test.

## 3. Risk management strategies and mitigations

Four treatments; pick one and write the reason and the owner.

| Treatment | MCP example |
|---|---|
| **Avoid** | Do not install a third-party server that needs shell access; drop a tool you do not use |
| **Mitigate** | Pin tool hashes; scope checks; vault; gateway; sandbox; approval for writes |
| **Transfer** | Vendor contract and attestation for a remote server; cyber insurance |
| **Accept** | Loopback HTTP without TLS, with token auth, owner signs for 12 months |

Defences by finding family (all built and tested in [Chapter 4](../ch4-defending-and-hardening-mcp-servers/README.md)):

| Family | Controls | Ch4 lab |
|---|---|---|
| Tool poisoning, rug pull, shadowing | Scan, pin, namespace, allowlist | `defend-tool-poisoning`, `defend-rug-pull`, `defend-tool-confusion` |
| Scope creep, passthrough | Scopes per tool, audience binding | `defend-oauth-scopes`, `least-privilege-tools` |
| Secrets | Vault, redaction | `secrets-vault` |
| No audit | Structured and signed log | `tool-invocation-logging` |
| Injection in results, over-sharing | AI firewall | `mcp-ai-firewall` |

## 4. Communicating threat model outputs to stakeholders

Different readers need different outputs.

| Reader | They need | Give them |
|---|---|---|
| Executives | Is it safe to launch, what does it cost, what do you need from me? | One page ([template](exec-summary-template.md)): bottom line, top 5 risks in plain words, decisions needed |
| Product owner | What delays the release? | Findings that block release, with the smallest fix |
| Engineers | What exactly to change? | Findings table with element, flow id, control and test |
| Auditors | Proof of method and follow-up | Register with owners, dates, residual rating, evidence links |
| Vendor of a server | What do you ask of us? | A short questionnaire from the missing controls |

Rules: lead with the decision, not the method; use plain words ("a hostile web page could call our database tool"); show inherent and residual; state assumptions and limits; give dates and owners.

### Findings table (copy into your report)

| ID | Element / flow | STRIDE | Threat (plain words) | OWASP MCP | Inherent | Residual | Treatment | Owner | Due | Proof (test or evidence) |
|---|---|---|---|---|---|---|---|---|---|---|
| FND-036 | F2 host to LLM | T | A web page or tool result hides instructions that steer the agent | MCP06 | Critical | Critical | Mitigate: AI firewall + approval for side effects | Platform lead | Sprint 12 | `mcp-ai-firewall` tests |
| FND-013 | Token cache | I | OAuth tokens stored in a plain file | MCP01 | High | High | Mitigate: OS keychain | Desktop lead | Sprint 12 | Config test |

The lab produces the same columns automatically (`rate_risks.py --format csv`).

## 5. Quick check

1. Why report both inherent and residual risk?
2. Three findings are all High. Which do you fix first and why?
3. Rewrite "MT-S03 DNS rebinding on a loopback HTTP server" for an executive in one sentence.
4. Which treatment fits "we will accept the missing TLS on 127.0.0.1"? What must you record?

## 6. References

* OWASP Risk Rating Methodology (owasp.org/www-community/OWASP_Risk_Rating_Methodology).
* NIST AI RMF (AI 100-1) and SP 800-30 (risk assessment).
* [Module 07, lesson 03](../../07-ai-governance/03-ai-risk-management.md) in this repo.
