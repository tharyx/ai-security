# Real tool: IriusRisk for a multi-tier application and a multi-cloud system (hedged walkthrough)

> **Hedge.** IriusRisk is a commercial platform; a free **Community Edition** has been offered (verify editions, limits and terms at iriusrisk.com). Menu names below are approximate. Nothing here was run against a live IriusRisk instance by the course author. Use fictional systems; do not upload real architectures without approval. Only test systems you own or have written permission to test.

## Part A: multi-tier application

| Step | In IriusRisk (approximate) | Advice |
|---|---|---|
| 1 | Create a project (name, owner, data classification) | One project per system |
| 2 | Open the diagram editor; add trust zones (Internet, DMZ, Application, Data) | Zones drive many rules |
| 3 | Drag components: CDN/WAF, web application, REST API, database, message queue | Pick the most specific component type in the library |
| 4 | Draw data flows between tiers | The flows between tiers are where most threats are |
| 5 | Answer the questionnaires (authentication, data sensitivity, internet exposure) | Honest answers; they decide the threats |
| 6 | Review generated threats and countermeasures | Compare with the [offline lab](../labs/rules-engine-multitier-multicloud/README.md) output |
| 7 | Set countermeasure states (Required, Recommended, Implemented, Not applicable, Rejected) | "Rejected" needs a reason and a risk owner |
| 8 | Compare inherent and residual (current/projected) risk | Terminology varies by version |
| 9 | Push required countermeasures to Jira or Azure DevOps (if available in your edition) | Keep the link both ways |
| 10 | Generate the report | Technical and management views |

## Part B: multi-cloud

1. Create a project with one **trust zone per cloud** (AWS, Azure, Google Cloud) plus "Between clouds" and "On-premises" if relevant.
2. Use **provider components** from the cloud libraries (S3, Lambda, Azure Blob Storage, Azure Functions, Cloud Storage, Cloud Functions; verify names).
3. Model the **cross-cloud links** explicitly: data copy jobs, identity federation, shared secrets, VPN/interconnects.
4. Answer cloud questionnaires (public access, encryption keys, logging, identity).
5. Review provider-specific countermeasures; check the **shared responsibility** split per service.
6. Look for static credentials between clouds; prefer **workload identity federation**.
7. Map to standards your organisation needs (CIS benchmarks, PCI DSS, ISO 27001) if your edition supports it.

## Related

- Offline twin: [rules-engine-multitier-multicloud lab](../labs/rules-engine-multitier-multicloud/README.md).
- Another walkthrough for an MCP deployment: [CMCPSE IriusRisk walkthrough](../../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/iriusrisk-walkthrough.md).
- Multi-cloud controls: [multi-cloud control matrix](../../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md).
