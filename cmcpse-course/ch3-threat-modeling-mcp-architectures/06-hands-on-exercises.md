# Lesson 06: Hands-on exercises

> **Chapter 3** · **Time:** ~6 hours · four exercises that follow the course lab list.

| Course exercise | Where | What you do |
|---|---|---|
| Apply STRIDE to a provided MCP architecture and document findings | [`labs/stride-mcp-architecture/`](labs/stride-mcp-architecture/README.md) | Run the tool on the YAML, then document every finding in [`findings-template.md`](labs/stride-mcp-architecture/findings-template.md) |
| Risk rating exercise on STRIDE findings | [`labs/risk-rating/`](labs/risk-rating/README.md) | Rate, rank, build the register and the executive summary |
| Threat modeling with IriusRisk for an MCP deployment | [`labs/iriusrisk-walkthrough.md`](labs/iriusrisk-walkthrough.md) and [`labs/threat-dragon/`](labs/threat-dragon/README.md) | Follow the steps in IriusRisk (verify the edition you can use) or draw the same model in OWASP Threat Dragon |
| Threat Modeling with STRIDEGPT | [`labs/stridegpt/`](labs/stridegpt/README.md) | Run STRIDE GPT with your own key or local model, or the offline twin, then validate the AI output |

## Suggested order

1. Draw the DFD by hand from [lesson 02](02-diagramming-mcp-architectures.md) before you run any tool. Compare it to `--mermaid`.
2. Run the STRIDE tool. Document ten findings in detail and mark any false positives.
3. Rate and rank. Write the executive one-pager with [the template](exec-summary-template.md).
4. Run the AI twin and the validator. Add the misses by hand and decide which findings you disagree with.
5. Change the architecture (add a gateway and a vault: `controls: [ai_firewall, vault]`) and re-run to see residual risk fall.

## Self-check

* Can you explain why 13 of 18 flows cross a boundary in the sample?
* Which finding family is ranked first, and does that match your intuition?
* Which three MCP threats did the AI draft miss, and why do generic prompts miss them?
