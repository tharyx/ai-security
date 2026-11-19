# 02. Vetting and Managing Third-Party MCP Servers

> **Syllabus:** Vetting and Managing Third-Party MCP Servers: creating a vetting process, dependency analysis and risk scoring, scanning for known vulnerabilities, dependency pinning and version locking, mitigating dependency confusion in MCP ecosystems, automating the vetting of third-party MCP components.
> **Time:** 2 hours. **Labs:** [`sbom-mcp-server`](labs/sbom-mcp-server/README.md) (risk scoring), [`backdoor-mcp-package`](labs/backdoor-mcp-package/README.md) (pinning, diff review). **Read first:** [CAISP ch6 lesson 02](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md) and its [package-vetting lab](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) (general process, `pip-audit`, dependency confusion resolvers). This lesson adds the MCP specifics.

## 1. Creating a vetting process for third-party MCP packages

A vetting process answers: *may this server run in our environment, with which access, and who watches it?* Keep it light for low-risk servers and strict for servers that touch secrets, write data or send messages.

**Step 0. Intake.** One request form: server name, source URL, purpose, requesting team, data it will touch, credentials it needs, transport (stdio or remote), expected users. No form, no install.

**Step 1. Classify by impact.**

| Tier | Example | Review depth |
|---|---|---|
| 1 Low | Read-only access to public docs, no secrets, no network writes | Automated checks, owner approval |
| 2 Medium | Reads internal data, or can write to one system | Automated checks plus code skim plus sandbox test |
| 3 High | Sends messages, executes commands, touches credentials, finance or customer data | Full code review, pinned and mirrored build, legal/privacy review, gateway policy, re-review on every update |

**Step 2. Identity and provenance checks.** Who publishes it (a known vendor or an individual)? Is the package really from that repo (does the repo link back to the package, do release tags match)? Age, release history, number of maintainers, 2FA and signing, issue and PR hygiene, OpenSSF Scorecard result ([lesson 04](04-supply-chain-frameworks.md)). Names that imitate a vendor need extra care (postmark-mcp).

**Step 3. Technical checks (automatable, see section 6).**

- Dependency tree and known vulnerabilities (SBOM plus advisories).
- Licenses.
- Install scripts and network or process APIs in the code.
- **Tool inventory:** for each tool name, description, schema; run the [description scan](../ch5-devsecops-for-mcp-security/05-cicd-integration-and-policy-as-code.md); note tools that write, send or execute.
- SAST with the [MCP rules](../ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md).
- Secrets and hardcoded endpoints.
- Behavior test in a sandbox with canary data and a recording network ([backdoor lab](labs/backdoor-mcp-package/README.md)).

**Step 4. Decide and constrain.** Approve, approve with conditions, or reject. Conditions are concrete: pinned version and hash, container with read-only filesystem, egress allowlist, a scoped token, gateway policy (allowed tools only), a review date.

**Step 5. Register.** Record it in the AI/MCP inventory (see [07 AI inventory](../../07-ai-governance/01-ai-inventory-and-system-register.md)): owner, version, hash, tier, approval date, next review. An unregistered server is a **shadow server** ([lesson 07](07-emerging-threats-in-mcp.md)).

**Step 6. Re-vet on change.** A new version is a new package. Diff against the approved version; description changes need approval; scheduled reviews for tier 3.

**Step 7. Offboard.** Remove the config, revoke credentials, record the decision.

## 2. Dependency analysis and risk scoring

An MCP server's risk is its **own code plus its dependency tree plus how much power it holds**. A simple, explainable score helps rank work. The [`sbom-mcp-server` lab](labs/sbom-mcp-server/README.md) implements this table so you can see it run:

| Signal | Points | Why |
|---|---|---|
| Known vulnerability, critical / high / medium / low | 8 / 5 / 3 / 1 | Known exploitability |
| Unpinned (no exact version) | 3 | The content can change under you |
| No integrity hash | 1 | Cannot verify what you got |
| Registry not on the allowlist | 3 | Possible confusion or mirror abuse |
| Denied license | 2 | Legal risk |
| Unknown license | 1 | Legal uncertainty |
| Deep transitive dependency (depth 3 or more) | 1 | Harder to review, easy to overlook |

Add **server-level** factors when you rank whole servers rather than packages: tier (the power it holds), publisher trust, maintainer count, last release age, presence of install scripts, number of tools that write or send. Keep the formula **transparent and versioned**: a number nobody can explain gets ignored. Set a threshold per tier (for example "tier 3 needs a worst-component score of 2 or less, or a documented waiver").

Risk scoring is a **triage aid**. A score of zero does not mean safe (postmark-mcp had no known vulnerabilities).

## 3. Scanning MCP server packages for known vulnerabilities

- **SCA tools:** `pip-audit` (Python), `npm audit` (Node), OSV-Scanner (many ecosystems, uses the OSV database), Trivy and Grype (images and file systems), GitHub Dependabot alerts, Snyk (verify current features).
- **What they find:** known CVEs in dependencies. **What they do not find:** a brand-new malicious package, a backdoor in the server's own code, a poisoned description. Combine with diff review, behavior tests and description scans.
- **Reachability:** a vulnerable function the server never calls is lower priority. Not all tools tell you.
- **Scan the container too:** the base image and OS packages count.
- **Schedule:** on intake, on each update, and nightly for approved servers (new advisories appear later).

Lab: the pipeline's [`deps` stage](../ch5-devsecops-for-mcp-security/labs/mcp-cicd-pipeline/README.md) and the `sbom-mcp-server` analysis both match a local advisory file. General practice: [CAISP third-party-vulns lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md).

## 4. Dependency pinning and version locking for MCP servers

| Layer | Do |
|---|---|
| **Host config** | Pin the server itself: `npx some-mcp@1.4.2` (not `@latest`, not a range); `uvx some-mcp==1.4.2`. Avoid `-y` so a human sees the first install. Better: install from your **internal mirror** and launch the local copy |
| **The server's own deps** | Lock file with exact versions and hashes: `pip install --require-hashes -r requirements.lock`; `npm ci` with `package-lock.json`; `uv.lock` |
| **Containers** | Pin the image by **digest** (`image@sha256:...`), not by tag |
| **GitHub Actions** | Pin by full commit SHA ([ch5 lesson 06](../ch5-devsecops-for-mcp-security/06-pipeline-attacks-on-mcp.md)) |
| **Tool metadata** | Hash of each tool's description and schema, with an approval workflow ([ch5 lesson 05](../ch5-devsecops-for-mcp-security/05-cicd-integration-and-policy-as-code.md)) |
| **Updates** | Deliberate: a bot opens a PR, the pipeline vets the new version (diff, scan, behavior test), a human approves |

Pinning protects only if you also **review updates**. A pinned old version with a known CVE is its own risk; the answer is a controlled update path, not `@latest`.

## 5. Mitigating dependency confusion in MCP ecosystems

**Dependency confusion:** your build asks for a package name; an attacker has published a *same-named, higher-versioned* package on a public index, and the resolver picks it. Details and the resolver lab: [CAISP ch6 lesson 02, section 4](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md) and `depconfusion.py`.

MCP-specific angles:

- Companies publish **internal MCP servers** with names like `acme-crm-mcp`. If the name is not registered publicly, an attacker can register it.
- Host configs reference **bare names** (`npx acme-crm-mcp`) that resolve against the **public** registry by default.
- Agents (and AI assistants writing configs) **invent plausible server names** (slopsquatting).
- Registries differ in namespace rules: scoped npm names (`@acme/crm-mcp`) tie a name to an organization; the official MCP Registry verifies namespace ownership (verify current rules).

Controls:

1. **Use scoped or namespaced names** for internal servers, and **register the names on the public registries too** (placeholder packages) where practical.
2. **Point the package manager at your internal registry** with a rule that internal scopes never resolve publicly (`.npmrc` scope to registry mapping; pip: `--index-url` your mirror, avoid `--extra-index-url`, or use a proxy with namespace rules; verify per tool).
3. **Lock with hashes** so a substituted package fails.
4. **Allowlist** which packages may be launched by host configs (policy as code, [ch5](../ch5-devsecops-for-mcp-security/05-cicd-integration-and-policy-as-code.md)).
5. **Alert on first-seen names** in builds and host configs.

## 6. Automating the vetting of third-party MCP components

Automate the deterministic parts, keep humans for decisions. A vetting pipeline for a *candidate* package:

```text
intake -> fetch (in a sandbox) -> SBOM -> advisory match + license check -> install-script scan
       -> tool inventory + description scan -> MCP SAST -> sandbox behavior test with canaries
       -> risk score -> policy decision (auto-approve tier 1 / queue tier 2-3 for a human) -> register + pin
```

Rules for the automation itself: fetch and analyse in an **isolated, network-restricted environment** (you are about to open untrusted code); never run the package's install scripts on a trusted machine; record versions and hashes of what was analysed; re-run on every new version; write the decision and its inputs into an audit log.

Lab pointers: [`sbom-mcp-server`](labs/sbom-mcp-server/README.md) covers SBOM, advisory matching, license, unpinned and registry checks and scoring; [`backdoor-mcp-package`](labs/backdoor-mcp-package/README.md) covers diff review, behavior tests, egress allowlists and pinning.

## 7. Interview questions

- *Design a vetting process for a third-party MCP server that can send email.* Tier 3: intake, publisher and provenance checks, SBOM and scan, full code review of the send path, description scan, sandbox behavior test with a recording transport (exactly the recipients requested), pinned version and hash, egress allowlist on recipient domains, gateway policy, inventory entry, re-review on every update.
- *Why is `@latest` dangerous?* It silently installs new, unreviewed code; postmark-mcp's malicious version reached users that way.
- *What does a risk score not tell you?* Whether the code is malicious. It ranks known, measurable signals.

## 8. References

- [CAISP ch6 lesson 02](../../caisp-course/ch6-supply-chain-attacks-in-ai/02-vetting-software-frameworks.md); [CAISP package-vetting lab](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/)
- OSV (osv.dev), pip-audit, npm audit documentation (verify current).
