# 01. The MCP Supply Chain: Stages, Registries, Attack Vectors and Incidents

> **Syllabus:** Overview of the MCP Supply Chain: components and stages of the MCP supply chain, third-party MCP package registries and their risks, attack vectors introduced by the MCP supply chain, real-world supply chain incidents relevant to MCP.
> **Time:** 2 hours. **Lab:** [`backdoor-mcp-package`](labs/backdoor-mcp-package/README.md). **General background:** [CAISP ch6 lesson 01](../../caisp-course/ch6-supply-chain-attacks-in-ai/01-supply-chain-overview-and-ai-attacks.md) (supply chain basics, AI-specific attacks).

## 1. Why this matters

With MCP, adding a capability to an agent often means running **someone else's code with your credentials**: `npx some-mcp-server` in a config file, and the agent can now read your mail or your repo. The convenience that makes MCP popular (a catalogue of ready servers) is the same thing that makes the supply chain the top practical risk (OWASP MCP04: Software Supply Chain Attacks and Dependency Tampering).

## 2. The stages of the MCP supply chain

```text
 source  ->  package  ->  registry  ->  install / launch  ->  runtime update  ->  agent use
 (repo)     (npm, PyPI,   (npm, PyPI,    (npx, uvx, pipx,     (auto-update,      (tools, descriptions,
            image, binary) MCP registries, docker run, git     @latest, remote     resources enter the
                           aggregators)   clone, host config)  server changes)     model context)
```

| Stage | What can go wrong | Example controls |
|---|---|---|
| **Source** | Compromised maintainer account; malicious pull request; stolen signing key; abandoned repo taken over | 2FA, signed commits, branch protection, reviews, OpenSSF Scorecard checks |
| **Dependencies** | Vulnerable or malicious transitive packages; dependency confusion; typosquats | Lock files, hashes, audit, private mirror, allowlist ([02](02-vetting-third-party-mcp-servers.md)) |
| **Build** | Poisoned CI, tampered build tool, artifact not built from the claimed source | Hermetic builds, provenance, SLSA ([03](03-transparency-and-integrity.md), [04](04-supply-chain-frameworks.md)) |
| **Package** | The published artifact differs from the repo; hidden install scripts | Signing, reproducible builds, `ignore-scripts`, content diff |
| **Registry** | Fake or impersonating package; no namespace ownership check; fake popularity; takedown delay | Verified namespaces, vetted internal registry |
| **Install and launch** | `npx -y name` / `uvx name` runs the latest, unreviewed code with your user rights; the **host config** is the control point | Pin exact versions, verify hash/signature, run in a container or sandbox |
| **Runtime update** | A server changes tool descriptions or behavior later (rug pull); remote servers change with no new install at all | Description pinning and alerts, version pinning, gateway |
| **Agent use** | Tool descriptions and results flow into the model's context: poisoning and injection | [Chapter 4](../ch4-defending-and-hardening-mcp-servers/README.md) controls, [firewall](../ch5-devsecops-for-mcp-security/07-ai-firewalls-at-the-gateway.md) |

Two MCP-specific points worth remembering:

1. **The install command lives in a config file** that many people copy from READMEs. `{"command": "npx", "args": ["-y", "some-mcp"]}` means "download whatever is latest today and run it". A version pin, a lock and a human review are missing by default.
2. **Remote (hosted) MCP servers have no install step at all.** You trust their *behavior over time*. A remote server can change a description tomorrow. That is the supply chain at runtime.

## 3. Third-party MCP registries and their risks

Servers are found through several kinds of catalogue:

| Source | What it is | Risk notes |
|---|---|---|
| Language registries (npm, PyPI) | Where most server packages actually live | Typosquatting, takeover, malicious versions, install scripts |
| **Official MCP Registry** | A community registry that launched in preview in 2025 (verify the current status). It verifies **ownership of a namespace** and lists server metadata; security scanning of the packages is left to the package registries and aggregators (verify) | A verified name is not a safe package. Metadata can be accurate while the package is bad |
| Third-party aggregators and "awesome" lists | Directories and marketplaces, some with one-click install | Variable vetting, fake or inflated popularity, stale entries, listing a repo is not reviewing it |
| Vendor catalogues in hosts/IDEs | Curated lists inside a product | Better odds, still check what runs and what it can reach |
| Docker images / OCI registries | Packaged servers | Base image risk, tag mutability: pin by digest |
| Git URLs and gists | Direct clone and run | No registry protections at all |

Registry risk summary: **identity** (who published this?), **integrity** (is this the code in the repo?), **mutability** (can a version be replaced or a tag moved?), **discovery** (search ranking and fake stars can be gamed), **removal** (how fast does a bad package disappear, and do you find out?).

## 4. Attack vectors introduced by the MCP supply chain

| Vector | How it works in MCP | Map |
|---|---|---|
| **Typosquatting / impersonation** | A package named like a real vendor's server (the `postmark-mcp` case copied a real company's name) | MCP04 |
| **Malicious update after trust** | Several clean versions build trust, a later version adds a backdoor | MCP04 |
| **Dependency tampering / confusion** | A private or internal package name is claimed on the public index | MCP04 |
| **Tool poisoning via a third-party server** | Its descriptions steer the agent to misuse *other* servers' tools (shadowing) | MCP03 |
| **Rug pull** | The description or behavior changes after approval | MCP03/MCP04 |
| **Compromised developer tooling** | The inspector, proxy or helper tools around MCP have bugs | MCP07 / supply chain |
| **Malicious host config** | A shared config or "one-click install" link adds an attacker's server | MCP04 / MCP09 |
| **Install-time code** | `postinstall` scripts, `setup.py` code, Docker `ENTRYPOINT` | MCP04 |
| **Slopsquatting** | Names an AI assistant hallucinated are registered by attackers ([CAISP ch6 01](../../caisp-course/ch6-supply-chain-attacks-in-ai/01-supply-chain-overview-and-ai-attacks.md)) | MCP04 |
| **Poisoned CI/CD of a legitimate server** | The maintainer's pipeline is attacked ([ch5 lesson 06](../ch5-devsecops-for-mcp-security/06-pipeline-attacks-on-mcp.md)) | MCP04 |

## 5. Real-world incidents relevant to MCP

Sources are mostly security vendors and researchers; details and numbers differ between reports. **Verify against the original advisories before quoting them.**

### 5.1 postmark-mcp (September 2025): the anchor case

- **What:** an npm package named `postmark-mcp` impersonated the email service Postmark. Reportedly, the first versions (about fifteen) behaved normally; version **1.0.16** added a line that **BCC'd every email sent through the tool to an address controlled by the attacker**. Koi Security reported it; Snyk and others wrote it up; the package was removed from npm. It is widely described as the **first known malicious MCP server in the wild**.
- **Why it worked:** the tool's name, description and schema never changed. Nothing in the *interface* looked different. Installed with `npx`, people who had not pinned a version got the new code. The malicious change was a few lines in the code.
- **Lessons:** pin exact versions; **diff** updates before accepting them; test **behavior** (the tool should send exactly one email to the requested recipient); allowlist **egress** (recipients, hosts); verify who publishes the package; do not rely on description pinning alone, since the description did not change.
- **Lab:** [`backdoor-mcp-package`](labs/backdoor-mcp-package/README.md) reproduces the *idea* (a simulated package, a canary body, a recording transport, nothing sent) and shows four defences.

### 5.2 mcp-remote, CVE-2025-6514 (JFrog, 2025)

`mcp-remote` is a popular helper that lets local-only clients talk to remote MCP servers. Researchers at JFrog reported that a malicious or compromised **server** could return a crafted `authorization_endpoint` during the OAuth step that led to **operating-system command execution on the client machine** (critical severity, about 9.6; fixed in 0.1.16). Lesson: the *client side* and helper tools are supply chain too, and a remote server is untrusted input. Update tools, and connect only to servers you trust.

### 5.3 Other MCP incidents to know (brief)

| Incident | Summary | Supply-chain lesson |
|---|---|---|
| **MCP Inspector, CVE-2025-49596 (Oligo, 2025)** | No authentication between the Inspector UI and its local proxy allowed remote code execution from a web page via CSRF (critical, about 9.4; fixed in 0.14.1) | Developer tools are in scope; update them; do not expose them |
| **Anthropic Filesystem MCP server, CVE-2025-53109 / 53110** | Symlink and path-prefix bypasses of the directory sandbox | Even reference servers have bugs; sandbox and patch |
| **Asana MCP (June 2025)** | A logic flaw in the experimental MCP server exposed some customers' data to others; the feature was disabled while fixed | Vendor-hosted MCP servers carry multi-tenant risk. Ask vendors about isolation |
| **Invariant Labs research (2025)** | Tool poisoning (April), WhatsApp MCP exfiltration (April), GitHub MCP private-repo leak through a public issue (May) | Third-party servers can steer agents against your other tools |
| **tj-actions/changed-files (March 2025, not MCP)** | CI action compromised to leak secrets; reported | Same trust problem in the build chain; pin by SHA |

### 5.4 Pattern across all of them

Trust was given once (at install, or at first approval) and then **never re-checked**. Every control in this chapter re-checks something: the version, the hash, the signature, the provenance, the behavior, the description.

## 6. Hands-on

1. Open your own MCP host config (Claude Desktop, Cursor, VS Code or similar; the file location differs by product and platform, check the product docs). List each server: command, package, version pin, who maintains it, what credentials it receives. How many are unpinned?
2. Run the [`backdoor-mcp-package` lab](labs/backdoor-mcp-package/README.md) and explain in two sentences why a description pin would **not** have stopped it.

## 7. Interview questions

- *Name the stages of the MCP supply chain and one control for each.* Source (2FA, signed commits), dependencies (lock + audit), build (provenance), package/registry (verified publisher, signing), install (pinned versions), runtime (description pinning, gateway).
- *What was special about postmark-mcp?* Trust built across clean versions, interface unchanged, tiny code change, installed by unpinned `npx`.
- *Does a "verified" namespace in a registry mean the package is safe?* No. It proves who owns the name, not that the code is benign.

## 8. References

- Koi Security and Snyk write-ups on `postmark-mcp` (Sept 2025); JFrog on CVE-2025-6514; Oligo on CVE-2025-49596 (verify details at the original sources and NVD).
- OWASP MCP Top 10 (beta): MCP04, MCP09. [Repo: 04 secure-operations](../../04-mcp-security/secure-operations/README.md) (registry allowlist, tampered packages).
