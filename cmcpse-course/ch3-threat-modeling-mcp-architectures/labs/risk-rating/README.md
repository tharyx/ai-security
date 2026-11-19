# Lab: risk rating for the STRIDE findings

**Course exercise:** Risk rating exercise on STRIDE findings.
**Runs offline.** Tests: `test_rate_risks.py` (12 tests). It imports the STRIDE lab next door.

| File | Role |
|---|---|
| [`rate_risks.py`](rate_risks.py) | OWASP-style rating (likelihood × impact), inherent and residual, ranking, treatment, register, executive summary |
| [`demo.py`](demo.py) | Prints counts, the top 8 and the executive summary |
| [`../../exec-summary-template.md`](../../exec-summary-template.md) | The blank one-pager for your own write-up |

## Method in one screen

```text
likelihood = mean(agent, vuln)    impact = mean(technical, business)     LOW <3, MEDIUM 3-<6, HIGH 6+
crossing a boundary: agent +1     each control present: vuln -3 (min 1)   business >= max asset value touched
severity = OWASP matrix (Note / Low / Medium / High / Critical)         ranked by residual severity, score, id
```

## Run

```bash
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating/demo.py
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating/rate_risks.py --format csv > register.csv
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/risk-rating/rate_risks.py --exec > exec-summary.md
```

Real demo output (trimmed):

```text
Inherent: {'Critical': 5, 'High': 40, 'Medium': 17, 'Low': 0, 'Note': 0}
Residual: {'Critical': 5, 'High': 37, 'Medium': 20, 'Low': 0, 'Note': 0}
1. FND-044 Critical F7 git server (stdio) -> AI host with MCP client: Indirect prompt injection inside a tool result
```

## Your task

1. Read the ranked register. Do you agree with the top 10? Write down three ratings you would change and why.
2. Change one factor in `mcp_threat_library.yaml` (for example lower the agent factor of `MT-S03`), re-run, and explain the change.
3. Edit the architecture to add `ai_firewall` and `tool_pinning` on the host. Compare inherent and residual counts.
4. Fill the executive one-pager for the sample system in under one page.
5. Pick the treatment for five findings (avoid, mitigate, transfer, accept) and write the reason.

## Note on calibration

The factor values are teaching numbers. On an uncalibrated scale most findings land in High, so the lab keeps Critical for the few cases where both likelihood and impact are HIGH. In a real review, calibrate the factors with your team and keep a written scale.
