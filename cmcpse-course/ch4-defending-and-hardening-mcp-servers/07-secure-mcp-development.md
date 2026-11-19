# Lesson 07: Secure MCP server development practices

> **Chapter 4** · **Time:** ~3 hours · **You will:** write an MCP server with secure coding practices, manage dependencies safely, handle errors without disclosure, test security during development, and review code with a checklist.

| | |
|---|---|
| **Syllabus lines** | Secure MCP Server Development Practices (5 lines) |
| **Already in this repo** | Vulnerable and secure server pairs: [Module 04, tool-security](../../04-mcp-security/tool-security/README.md); CI/CD gates, SBOM and signing: [Module 06, CI/CD](../../06-ai-devsecops/cicd/README.md); SAST/DAST and PPE: [CAISP ch4](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md) |
| **This lesson adds** | An MCP-specific coding and review view and the [code review checklist](code-review-checklist.md) |
| **Next chapter** | [Chapter 5: DevSecOps for MCP](../ch5-devsecops-for-mcp-security/README.md) |

---

## 1. Secure coding practices for MCP server implementation

1. **Identity from the session, not the arguments.** Derive user, tenant and role from the verified token. Ignore `user_id` or `role` in tool input (or reject extra fields with `additionalProperties: false`).
2. **Strict schemas plus server-side validation.** Check type, length, range and enum again in code. Canonicalise paths and URLs before checks ([lesson 03](03-secure-tool-and-resource-design.md)).
3. **No shell, no string-built SQL.** `subprocess.run([...], shell=False)`; parameterised queries; no `eval`, `exec`, `pickle.loads` or `yaml.load` on untrusted data (use `yaml.safe_load`).
4. **Constant-time comparison for secrets** (`hmac.compare_digest`); generate tokens with `secrets`, not `random`.
5. **Deny by default.** Policy tables with an explicit allow; unknown tool, role or resource is refused.
6. **Authorise at the point of use** (each call), plus filter lists.
7. **Output minimisation and sanitisation.** Return only needed fields; strip secrets.
8. **Bound everything:** request size, result size, rows, time, concurrency, recursion depth.
9. **Outbound requests:** allowlist hosts, resolve and check IPs (block private ranges and the metadata address), limit redirects (SSRF).
10. **File access:** a root directory, resolved real paths (symlinks), no writes outside a scratch area, no following links out of the root (the filesystem server CVEs of 2025, CVE-2025-53109 and CVE-2025-53110, were reported as symlink and prefix bypasses; verify details).
11. **Concurrency and state:** do not share per-user state between sessions (the MCP10 context bleeding bug class); key caches by tenant and user.
12. **Secrets from a vault at call time**; never in schemas or logs ([lesson 05](05-secrets-management.md)).
13. **Logging with context and redaction** ([lesson 06](06-logging-monitoring-detection.md)).
14. **Least-privilege runtime:** non-root user, container with a read-only root, dropped capabilities, minimal network.

## 2. Safe dependency management

MCP servers are installed from public registries by users who rarely read the code. Reported incidents include a malicious `postmark-mcp` npm package (September 2025: after benign versions, a later release added a hidden BCC; secondary reports, verify) and a critical flaw in `mcp-remote` (CVE-2025-6514). Your server is a supply chain link for others.

For **your** server:

* **Minimise dependencies**; prefer the official SDK (`mcp` for Python, the TypeScript SDK) and well-maintained libraries.
* **Pin and lock:** `requirements.txt` with hashes (`pip-compile --generate-hashes`, `pip install --require-hashes`), `package-lock.json` with `npm ci`, a lockfile for `uv`.
* **Scan:** `pip-audit`, `npm audit`, OSV-Scanner, Dependabot or Renovate; fail CI on known high vulnerabilities (verify tool options).
* **SBOM** (CycloneDX or SPDX) per release, and **signed releases** (sigstore/cosign; trusted publishing on PyPI and npm provenance; verify). See [Module 06, CI/CD](../../06-ai-devsecops/cicd/README.md) and the supply chain chapter in [CAISP ch6](../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md).
* **Beware dependency confusion and typosquats:** scope your package names (`@org/name`), reserve names, review new dependencies in PRs.
* **Lock the install command in docs:** tell users to install an exact version and show the digest. Do not teach `npx -y name` with no version.
* **Release hygiene:** two-person review, protected branches, 2FA on registry accounts, no long-lived publish tokens in CI (use short-lived OIDC), a SECURITY.md and a way to report vulnerabilities.
* **Never auto-update tool definitions silently.** A change to a description or schema is a security-relevant change; announce it, bump the version, and expect clients to re-pin ([`defend-rug-pull`](labs/defend-rug-pull/README.md)).

## 3. Error handling to prevent information disclosure

| Do | Do not |
|---|---|
| Return a short, generic message to the client (`"Internal error."`, `"Secret backend unavailable."`) with an error code and a correlation id | Return stack traces, SQL text, file paths, hostnames, library versions or raw exception strings |
| Log details **server-side**, redacted, with the same correlation id | Log secrets or full request bodies |
| Use the same response for "does not exist" and "not allowed" where existence is sensitive | Reveal which resource exists |
| Fail **closed**: a failed policy lookup means deny | Continue with defaults |
| Catch broad exceptions at the tool boundary and map them to safe errors | Let framework debug pages leak |
| Log the exception **class** only when the message could hold secrets | Print `repr(exc)` of exceptions that wrap credentials |

MCP detail: a tool can report an execution error inside the result (`isError: true`) so the model can react, or return a JSON-RPC error for protocol problems. The text in either is **model-visible**, so apply the same disclosure rules. The vault lab returns "Secret backend unavailable. Try again later." and logs the redacted detail.

## 4. Security testing during the development process

Build the checks into the normal loop:

| Stage | Practice | Tooling (verify) |
|---|---|---|
| Write | Unit tests for **each control**, including negative tests: wrong audience, hidden tool call, `..` path, extra argument, oversized input | `pytest`; see any lab in this chapter |
| Write | Property tests for parsers and validators | `hypothesis` |
| Commit | Secret scan, lint, formatting | pre-commit, gitleaks |
| PR | SAST | Semgrep, CodeQL, Bandit |
| PR | Dependency and licence scan, SBOM diff | pip-audit, OSV-Scanner, Syft |
| Build | Reproducible build, sign, attest | cosign, SLSA provenance |
| Test env | **Schema and fuzz tests** of tool inputs; a poisoned-definition fixture run through the scanner; a rug-pull fixture; a tool-confusion fixture | the chapter 4 labs as templates |
| Test env | **Integration tests** with a malicious client: no token, wrong audience, expired token, over-scoped token, replay | [`defend-oauth-scopes`](labs/defend-oauth-scopes/README.md) |
| Test env | **Prompt-injection regression set** through the firewall | [`mcp-ai-firewall`](labs/mcp-ai-firewall/README.md) |
| Pre-release | DAST against the HTTP endpoint, TLS configuration scan, MCP Inspector or a custom client for manual probing (never expose the Inspector itself) | OWASP ZAP, testssl.sh |
| Release | Threat model update ([chapter 3](../ch3-threat-modeling-mcp-architectures/README.md)), security review, penetration test for high risk | |
| Run | Detections and canary secrets | [lesson 06](06-logging-monitoring-detection.md) |

Use **canaries**: plant fake secrets (`CANARY-...`) in data and assert they never show up in results, logs or errors. Test **every finding** from your threat model with at least one test that fails when the control is removed.

## 5. Code review checklist for MCP servers

Use the full list in [`code-review-checklist.md`](code-review-checklist.md). Reviewers answer yes or no to each item and link a test. Highlights:

* Tool list is minimal, narrow and read/write separated.
* Every tool has a scope or role and is denied by default; enforced at list **and** call.
* Schemas strict; server-side validation; no shell or string SQL; paths and URLs canonicalised.
* Identity, tenant and role come from the verified session.
* No secrets in schemas, env, logs or errors; vault at call time.
* Outputs minimal; sanitised; size-bounded.
* Logging with context, redaction and denials.
* Dependencies pinned, scanned, SBOM produced.
* Tests exist for each control and for each finding.

## 6. Quick check

1. Name three things a reviewer should look for in a tool's `description` besides spelling.
2. Why is `npx -y package` in a README a supply chain problem?
3. What should the model see when the database is down?
4. List two negative tests you would write for an OAuth-protected server.

## 7. References

* OWASP ASVS and Secure Coding Practices Quick Reference; OWASP Top 10 (2021) for web basics.
* MCP specification and SDK documentation (verify current versions).
* SLSA framework; Python Packaging "trusted publishers"; npm provenance (verify).
* [Module 04](../../04-mcp-security/README.md), [Module 06](../../06-ai-devsecops/cicd/README.md).
