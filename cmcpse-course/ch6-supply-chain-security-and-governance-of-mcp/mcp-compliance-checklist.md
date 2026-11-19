# MCP Deployment Compliance Checklist

Use for one deployment (agents + hosts + servers + data). Mark each row **Done / Partial / Missing / N/A** and write the **evidence** (a link, a ticket, a file). Not legal advice: have counsel confirm the regulatory rows. Reference: [lesson 06](06-compliance-and-regulation.md).

**Deployment:** `<name>` **Owner:** `<name>` **Date:** `<date>` **Reviewer:** `<name>` **Tier:** `<1/2/3>`

## A. Scope, inventory and ownership

| # | Check | Status | Evidence |
|---|---|---|---|
| A1 | The AI system boundary is drawn (host, models, servers, tools, data, users) | | |
| A2 | Every MCP server is in the inventory with owner, version, hash, tier, transport, credentials, data classes | | |
| A3 | Discovery found no shadow servers (endpoint config scan, repo scan, network check) in the last 90 days | | |
| A4 | Each server has a named owner and a backup | | |
| A5 | A decommissioning process exists (config removal, credential revocation) | | |

## B. Risk and impact

| # | Check | Status | Evidence |
|---|---|---|---|
| B1 | Threat model exists and is current (DFD, STRIDE, abuse cases) | | |
| B2 | Each tool is classified: read / write / execute / send / spend | | |
| B3 | Impact assessment done for tools that write, send or act on people | | |
| B4 | Risks are in a register with owners, ratings and dates | | |
| B5 | Human-oversight points are defined (which calls need approval, by whom) | | |

## C. Supply chain

| # | Check | Status | Evidence |
|---|---|---|---|
| C1 | Third-party servers passed the vetting process; decision recorded | | |
| C2 | Versions pinned in host configs (no `@latest`, no unpinned `npx`/`uvx`); image digests pinned | | |
| C3 | Lock files with hashes; installs from the approved registry or mirror | | |
| C4 | SBOM generated and stored per release; reviewed for new components | | |
| C5 | Dependency vulnerability scan in CI and nightly; SLAs for fixes | | |
| C6 | Signatures or provenance verified at deploy (or own build signed) | | |
| C7 | Tool descriptions and schemas pinned; changes need approval | | |
| C8 | Update path defined: diff, scan, behavior test, approval | | |

## D. Security controls

| # | Check | Status | Evidence |
|---|---|---|---|
| D1 | Secure SDLC: SAST, secret scanning, review checklist, MCP rules | | |
| D2 | DAST/fuzzing/pentest performed with findings tracked | | |
| D3 | Authentication and authorization per user and per tool; no token passthrough | | |
| D4 | Least-privilege credentials, short-lived where possible, in a vault | | |
| D5 | Servers sandboxed or containerized; egress allowlist | | |
| D6 | Gateway / AI firewall in place: tool allowlist, injection screening, output guardrails, rate limits | | |
| D7 | Servers bound to loopback or behind an authenticating gateway; TLS for remote | | |
| D8 | Pipeline security: protected branches, no secrets for untrusted code, pinned actions | | |

## E. Logging, monitoring and incidents

| # | Check | Status | Evidence |
|---|---|---|---|
| E1 | Tool-invocation logs (who, tool, argument hash, outcome) retained per policy; no secrets in logs | | |
| E2 | Alerts for blocked injections, description drift, unapproved servers, abnormal volume | | |
| E3 | Incident runbook covers poisoned tool, malicious update, leaked token, injection-driven data leak | | |
| E4 | Notification duties mapped (privacy regulators, customers, EU AI Act serious incidents if high-risk, CRA if applicable) | | |
| E5 | Kill switch tested (disable a server or tool quickly) | | |

## F. Data protection and privacy

| # | Check | Status | Evidence |
|---|---|---|---|
| F1 | Personal data flows through tools, prompts, logs and caches are mapped | | |
| F2 | Legal basis, purpose limitation and retention defined | | |
| F3 | DPIA / privacy assessment done where required | | |
| F4 | Processor and sub-processor terms in place with hosted MCP vendors | | |
| F5 | Cross-border transfer controls checked | | |

## G. Transparency and documentation

| # | Check | Status | Evidence |
|---|---|---|---|
| G1 | Documentation lists tools, permissions and data per server (an "MCP BOM") | | |
| G2 | Users are told they interact with AI where required (chatbots, synthetic content marking) | | |
| G3 | Model cards or provider documentation on file for models used | | |
| G4 | Customer-facing security and AI statements match reality | | |

## H. Regulatory screening (confirm with counsel)

| # | Check | Status | Evidence |
|---|---|---|---|
| H1 | EU: role(s) identified (provider, deployer, supplier); MCP servers classified as component vs AI system; memo on file | | |
| H2 | EU: any prohibited practice excluded; AI literacy training done | | |
| H3 | EU: if high-risk (Annex III/I), requirements and dates mapped (verify Omnibus dates); suppliers bound by written agreements | | |
| H4 | EU: transparency duties (Article 50) assessed | | |
| H5 | US: state laws touched (for example automated decision laws, frontier AI transparency) assessed; federal sector rules assessed | | |
| H6 | Other law: GDPR/DPDP, CRA (commercial products), NIS2, sector rules assessed | | |
| H7 | Management-system alignment (ISO 42001 / 27001) and NIST AI RMF mapping recorded | | |

## I. Governance rhythm

| # | Check | Status | Evidence |
|---|---|---|---|
| I1 | Review dates set (quarterly for tier 3) and last review recorded | | |
| I2 | Re-assessment triggers defined (new model, new tool class, new regulation, incident) | | |
| I3 | Metrics reported to the risk owner | | |
| I4 | Training completed by developers, users and approvers | | |

## Sign-off

| Role | Name | Date | Decision (Approve / Approve with conditions / Reject) |
|---|---|---|---|
| Server owner | | | |
| Security reviewer | | | |
| Privacy / legal | | | |
| Risk owner | | | |
