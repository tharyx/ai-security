# Executive one-pager: MCP deployment threat model (template)

> Copy this file. Replace every `<...>`. Keep it to one page. Generate the numbers with
> `python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating/rate_risks.py --exec`.

**System:** `<name and one-line purpose>` · **Date:** `<date>` · **Owner:** `<name>` · **Review by:** `<date>`

## 1. Bottom line (two sentences)

`<Safe to launch / safe to launch with conditions / not safe yet>`, because `<the single biggest reason, in plain words>`.
We need `<decision>` from you by `<date>`.

## 2. What we reviewed

`<N>` MCP servers (`<local>` local, `<remote>` remote), `<N>` data flows, `<N>` trust boundaries. Assets that matter most: `<tokens, customer data, ...>`.

## 3. Top five risks

| # | Risk in plain words | Where | Severity now | Severity after fix | What we propose |
|---|---|---|---|---|---|
| 1 | `<A hostile web page or document can steer our agent into leaking data>` | `<flows F2, F5>` | `<Critical>` | `<Medium>` | `<Gateway with output filtering and approval for sends>` |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

## 4. Decisions needed

| Decision | Options | Our recommendation | Cost / effort | Deadline |
|---|---|---|---|---|
| `<Approve the gateway>` | `<Build, buy, accept risk>` | `<Build>` | `<2 engineers, 3 weeks>` | `<date>` |

## 5. Numbers

| Severity | Before controls | Today | After plan |
|---|---|---|---|
| Critical | `<n>` | `<n>` | `<n>` |
| High | `<n>` | `<n>` | `<n>` |
| Medium | `<n>` | `<n>` | `<n>` |

## 6. Assumptions and limits

* Ratings are informed estimates from a library of generic MCP threats, not measurements.
* New servers, transports or scopes need a new review.
* Risks we accept: `<risk, owner, expiry date>`.

## 7. Next review

`<date or trigger, for example "when a new server is added">`
