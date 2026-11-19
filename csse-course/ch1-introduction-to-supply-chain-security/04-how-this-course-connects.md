# 04. How this course connects

> **Chapter 1 · Time:** 20 minutes. A map between the seven chapters, the repo and the earlier course companions.

## The seven chapters

| Chapter | Focus | Chapter 1 idea it builds on |
|---|---|---|
| 1 | Introduction: building blocks and threat model | (this chapter) |
| 2 | Attacking the code and application supply chain | Source, dependency and build threats for code, SCM and CI/CD |
| 3 | Attacking the container supply chain | The containers block |
| 4 | Attacking the Kubernetes cluster supply chain | The clusters block |
| 5 | Attacking the cloud supply chain | The cloud block |
| 6 | Common defenses | The control table in [lesson 01 section 3](01-supply-chain-overview-and-building-blocks.md#3-defend-it-one-control-family-along-the-whole-chain) |
| 7 | Managing a secure software supply chain program | Inventory, SLAs and regulation from [lesson 03](03-evolution-of-supply-chain-attacks.md) |

## Links to material you already have

- AI supply chain (models, datasets, AI-BOM): [CAISP chapter 6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) and [CMCPSE chapter 6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md). The same four threat families apply to models and MCP servers.
- Agent skills and marketplaces: [CAASE chapter 4](../../caase-course/ch4-computer-use-browser-and-coding-agents/README.md).
- Pipelines: [06-ai-devsecops/cicd](../../06-ai-devsecops/cicd/README.md), plus [poisoned pipeline execution](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md).
- Vulnerability prioritization (CVSS, EPSS, KEV): [cybersecurity track 08](../../cybersecurity-track/08-vulnerability-management/).
- Governance and evidence: [07 governance](../../07-ai-governance/), [08 compliance](../../08-ai-compliance/).

## How to use the rest of the course

For each later chapter ask the same four questions from [lesson 02](02-threat-model-of-the-software-supply-chain.md): what is the source, the dependency, the build and the distribution at this layer, and what hard control sits on each?
