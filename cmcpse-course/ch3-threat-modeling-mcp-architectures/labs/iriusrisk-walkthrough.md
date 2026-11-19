# IriusRisk walkthrough for an MCP deployment (conceptual, verify before use)

**Course exercise:** Threat modeling with IriusRisk for an MCP deployment.

**Hedge first.** IriusRisk is a commercial threat-modeling platform. The vendor has offered a free community edition in the past, but editions, limits and screens change. Verify what you can use at iriusrisk.com. This guide gives the *concepts and the order of steps*. Menu names are approximate. Follow your course lab for the exact clicks. Nothing here was run against a live IriusRisk instance by the repo author.

## What IriusRisk does (in general)

1. You build a **diagram** of the system with components (web app, database, API, queue, cloud services) and trust zones.
2. A **rules engine** adds **threats** and **countermeasures** from a built-in library, based on component types and answers to questions.
3. You **rate** and **prioritise** the threats (inherent and residual risk).
4. You mark countermeasures as required, recommended, implemented or not applicable, and track them (often with a ticketing integration).
5. You **report** (technical and management views).

This is the same flow as the lab tools: DFD, STRIDE per element, rating, register, report.

## Steps for the sample MCP deployment

| Step | In IriusRisk (approximate) | MCP-specific advice |
|---|---|---|
| 1. Create a product or project | New product with name, owner, data classification | Name it after the host, not after one server |
| 2. Build the diagram | Drag components onto the canvas and draw trust zones | Use the lab YAML as the source: host (application), each MCP server (a separate component), LLM provider (external or SaaS), registry (external), IdP, stores (database or file). Draw zones: workstation, local servers, SaaS vendor, internet |
| 3. Set component types and attributes | Pick the closest built-in type for each | A generic library has no MCP component (verify: a custom library may exist). Use "application" for servers and add notes such as `stdio`, `local HTTP`, `OAuth` |
| 4. Answer the questionnaire | Authentication, data sensitivity, hosting, protocols | Be honest about "no authentication on localhost" |
| 5. Generate threats | The engine produces threats and countermeasures | Compare with `stride_mcp.py`. Expect generic web-app threats and few MCP-specific ones |
| 6. Add custom threats | Create threats and countermeasures in a custom library, or add them manually | Add the MCP threats from [`mcp_threat_library.yaml`](stride-mcp-architecture/mcp_threat_library.yaml): tool poisoning, rug pull, tool shadowing, token passthrough, cross-server leakage, config command line |
| 7. Rate | Set likelihood and impact, or use the built-in risk model (verify which model it uses) | Use the same factors as [`risk-rating`](risk-rating/rate_risks.py) so results are comparable |
| 8. Treat | Mark countermeasures (implemented, required, rejected, in progress) | For "required" ones create tickets: pinning, scopes, vault, logging |
| 9. Report | Generate technical and management reports | Reuse [`exec-summary-template.md`](../exec-summary-template.md) for the narrative |
| 10. Re-model on change | Update the diagram when a server is added | Make it part of your server onboarding checklist |

## What to hand in or compare

* A screenshot or export of the diagram next to [`threat-dragon/mcp-architecture.mmd`](threat-dragon/mcp-architecture.mmd).
* The generated threats that are **not relevant** (false positives) and the MCP threats you had to add by hand.
* The residual-risk table before and after you mark countermeasures as implemented.

## Free alternatives

* **OWASP Threat Dragon:** see [`threat-dragon/README.md`](threat-dragon/README.md).
* **The lab tools in this folder:** `stride_mcp.py` and `rate_risks.py`.
* Other free options (verify): Microsoft Threat Modeling Tool (Windows), pytm (threat models as Python code), and Mermaid diagrams in your repo.
