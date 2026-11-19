# 04. Vetting Third-Party Harnesses, Models and Marketplaces

> **Chapter 6 · Time:** ~3 hours · **You will:** vet agent harnesses and orchestration frameworks, open-weight models and free models, and community skill/plugin marketplaces before you install or route traffic to them.
> **Labs:** [model-provenance-vetting](labs/model-provenance-vetting/README.md), [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md)
> **Maps to:** OWASP Agentic ASI04 Agentic Supply Chain · OWASP LLM 2026 LLM04 Supply Chain [2025: LLM03] · OWASP MCP04 Supply Chain · NIST AI RMF GOVERN · [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md) · [cmcpse ch6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md)

## 1. Why this matters

- **ClawHavoc (early 2026):** malicious skills were found on **ClawHub**, the skill marketplace of the OpenClaw agent. Koi Security's first audit flagged 341 of about 2,857 skills; later counts were higher; payloads were mostly infostealers (reported: AMOS on macOS). Numbers vary by source: verify.
- **OpenClaw exposure (early 2026):** a token-theft bug (CVE-2026-25253, CVSS about 8.8, patched) and large numbers of internet-exposed instances with insecure defaults were reported (SecurityScorecard cited about 135,000; counts vary). Renames also produced typosquat domains and packages.
- **postmark-mcp (Sept 2025):** an npm package impersonating Postmark added a hidden BCC after benign versions: the first known malicious MCP server in the wild.
- Models are supply chain too: malicious pickle models were found on public hubs (JFrog 2024; Wiz on Hugging Face, April 2024).
- Details: [ch4 skill-vetting](../ch4-computer-use-browser-and-coding-agents/labs/skill-vetting) for the single-skill view; this lesson adds scale and models.

## 2. Understand it

### 2.1 Vetting harnesses, orchestration frameworks and open or free models

| Artifact | Questions | Evidence |
|---|---|---|
| **Harness / framework** (Hermes Agent, OpenClaw and its hardened spin-offs, OpenCode, LibreChat, LangChain-style frameworks) | Who maintains it? Licence? Release signing? Default network exposure and auth? Does it run tools in a sandbox? Telemetry? How are skills/plugins loaded? Known CVEs? | Repo health (commits, maintainers, issues), release signatures and SBOM, security policy, a default-config review ([ch4 harness audit](../ch4-computer-use-browser-and-coding-agents/labs/harness-security-audit)), a trial in an isolated VM |
| **Open-weight model** | Publisher org verified? Hashes match? Format (safetensors vs pickle)? Licence permits your use? Model card and data disclosure? Eval results for injection and refusal? `trust_remote_code`? | Hash check, scan, licence review, own evals ([lab](labs/model-provenance-vetting/README.md)) |
| **Free model via a router** (for example OpenRouter free tiers) | What does the provider log or train on? Rate limits and reliability? Does the model support tool calling well? | Provider terms, data-policy flags, never send restricted data |

Hardening tools in the OpenClaw family (NemoClaw, NanoClaw, SecureClaw, MiniClaw; hedged, check each project): some add kernel-level sandboxing and out-of-process policy enforcement, some run audit checks mapped to OWASP ASI and ATLAS, some are lightweight variants. They reduce risk but they do not review the code of third-party skills; you still vet skills.

**Model sizing for your laptop (no GPU).** Memory is about parameters times bytes per weight (about 0.5 bytes at 4-bit, 2 at 16-bit) plus KV cache and overhead. A 4B model at 4-bit needs roughly 2.5 to 3.5 GB; chapter 1 has a calculator lab. Larger models: use a cloud router.

### 2.2 Vetting community skill and plugin marketplaces

A skill is **instructions plus scripts** the agent trusts. Treat installing a skill like running someone else's code with your agent's permissions.

| Signal | Example |
|---|---|
| Download-and-execute | curl output piped into a shell in setup steps |
| Credential access | reads SSH keys, cloud credential files, browser stores, wallets |
| Unknown network destinations | posts to a non-allowlisted domain |
| Obfuscation | long encoded blobs, hidden Unicode |
| Instructions aimed at the model | "ignore previous instructions", "do not tell the user" |
| Typosquatting | name one edit from a popular skill |
| Excess permissions | shell + network + filesystem with no justification |
| Unpinned installs | `pip install x` with no version |

Process: **scan at scale** (the [batch scanner](labs/marketplace-skill-batch-scan/README.md)), **review** the flagged ones, **pin** by hash, **allowlist** what you approve, **monitor** updates (rug pulls: a good version followed by a malicious one), run skills in a **sandbox with least privilege**, and prefer first-party or internally mirrored skills.

## 3. Defend it

| Layer | Control | Type |
|---|---|---|
| Intake | Allowlist of sources; internal mirror; no direct marketplace installs on production | Hard |
| Scan | Batch scan + human review; block on pipe-to-shell, credential paths, injection text | Hard + Process |
| Integrity | Pin by hash; verify signatures; AIBOM entries | Hard |
| Isolation | Sandbox; separate identity; egress allowlist | Hard |
| Models | Hash + format + licence + org + eval checks; route by decision (production, sandbox, reject) | Hard |
| Monitor | Update diffs, observability, kill switch | Process |

**What does NOT work on its own:** star counts or download counts; a marketplace "verified" badge you have not checked; scanning once and never again; trusting a skill because its README is well written.

## 4. Hands-on

1. [model-provenance-vetting](labs/model-provenance-vetting/README.md): six model cards, hashes, licences, org allowlist and evals produce a routing decision.
2. [marketplace-skill-batch-scan](labs/marketplace-skill-batch-scan/README.md): scan 300 synthetic skills, rank, and read the report.

## 5. Scenarios

1. *Cheap model, wrong licence.* A team routes production traffic to a non-commercial-licence model. Vetting rejects it for production and allows sandbox evaluation.
2. *Lookalike skill.* `pdf-tool` is one edit from `pdf-tools`. The scanner flags typosquat; reviewer finds an exfil URL.
3. *Rug pull.* A skill adds a pipe-to-shell step in v1.3. The hash pin fails the update until reviewed.

## 6. Interview questions

<details><summary><b>Q1. How do you vet an open-weight model before routing production traffic?</b></summary>
Verify publisher identity and compare file hashes with the published manifest; require a safe format (safetensors, not pickle); review the licence for your use; read the model card and data disclosure; run your own injection and safety evals; reject or sandbox anything that fails; record the decision in the AIBOM.
</details>

<details><summary><b>Q2. Why can you not trust a skill marketplace's popularity metrics?</b></summary>
Counts can be gamed and malicious skills have appeared on public marketplaces (ClawHavoc). Evaluate code and behavior, pin versions, and monitor updates.
</details>

<details><summary><b>Q3. What does a hardened harness (sandbox plus policy engine) not solve?</b></summary>
It limits what a skill can do but does not tell you whether a skill's instructions are malicious or whether it abuses permissions you granted. You still need vetting and least privilege.
</details>

## 7. Checklist

- [ ] No skill or model is installed from a marketplace without scan, review and pin.
- [ ] Production model routing requires a "production" decision with hashes verified.
- [ ] Skills run with a separate, minimal identity in a sandbox.

## 8. References

- Koi Security ClawHavoc research; SecurityScorecard exposure reports; OpenClaw advisories (verify counts and CVE details at source).
- [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md), [cmcpse ch6](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/README.md), [06 ai-devsecops](../../06-ai-devsecops/README.md).
- Next: [05 AIBOM, provenance and signing](05-aibom-provenance-and-signing.md).
