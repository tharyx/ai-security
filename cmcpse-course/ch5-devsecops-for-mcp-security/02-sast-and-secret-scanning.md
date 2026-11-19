# 02. Static Analysis of MCP Server Code: SAST, Secrets and Code Review

> **Syllabus:** Static Analysis of MCP Server Code: SAST tools applicable to MCP server codebases, identifying vulnerabilities in tool and resource implementations, scanning for hardcoded secrets, code review practices and checklists specific to MCP.
> **Time:** 2 hours. **Lab:** [`sast-vulnerable-mcp-server`](labs/sast-vulnerable-mcp-server/README.md).
> **General background (do not repeat):** [CAISP ch4 lesson 06, static analysis](../../caisp-course/ch4-ai-attacks-and-defenses-devops/06-devsecops-tooling-for-ai.md#static-analysis-of-models-and-applications) and its [ai-code-weaknesses lab](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md). This lesson adds the MCP rules.

## 1. Why this matters

Static analysis reads code without running it. It is the cheapest control and it finds the classic MCP bugs: a tool that passes text to a shell, a file tool that follows `../`, a "fetch this URL" tool that can reach the cloud metadata service. Public MCP servers have had these exact bugs (for example the path-prefix and symlink bypasses in the reference Filesystem server, CVE-2025-53109 and CVE-2025-53110, reported in 2025, and the command execution bug in `mcp-remote`, CVE-2025-6514; verify details at the CVE records).

## 2. SAST tools that fit MCP server codebases

An MCP server is ordinary code in Python, TypeScript/JavaScript, Go, Java, C# and others, so general tools apply. The skill is adding the MCP rules.

| Language | General SAST | Notes |
|---|---|---|
| Python | **Bandit**, **Semgrep**, CodeQL | Bandit has built-in checks for `shell=True`, `eval`, hardcoded passwords. Semgrep lets you write MCP rules in minutes. |
| TypeScript / JavaScript | Semgrep, CodeQL, ESLint with security plugins | Look for `child_process.exec`, `fs` with joined paths, `fetch` with a variable URL. |
| Go | gosec, Semgrep, CodeQL | |
| Any | **Secret scanners**: gitleaks, trufflehog, detect-secrets | See section 4. |
| MCP-specific | Scanners for MCP configs and tool descriptions (for example Invariant Labs' `mcp-scan`, now part of Snyk's agent security tooling; verify the current name and features) | They look at the *description* layer that normal SAST ignores. |

Ready-made rule packs change quickly: always check the current docs. In this repo you write the rules yourself, which is the best way to understand them.

## 3. The six MCP-specific rules (and the lab scanner that implements them)

| Rule | Looks for | Why it matters in MCP | Fix |
|---|---|---|---|
| **MCP001** shell exec | `os.system`, `subprocess(..., shell=True)`, `eval` on non-constants | The model's text becomes a command (MCP05) | Argument list, `shell=False`, allowlist pattern per value, or no shell tool at all |
| **MCP002** path join without canonicalization | `os.path.join(base, user)` or `Path(base) / user` without `resolve()`/`realpath` **and** a containment check | `../`, absolute paths, symlinks (CVE-2025-53109/53110 class) | Resolve, then `is_relative_to(base)`; reject otherwise |
| **MCP003** SSRF fetch | `urlopen`/`requests.get` with a variable URL and no allowlist call | The model can be told to fetch `http://169.254.169.254/` or an internal admin page | https only, exact-host allowlist, block IP literals and private ranges, re-check after redirects |
| **MCP004** secret in a description | Secret patterns or secret variables inside `description` | Descriptions go to every client and into the model context (MCP01) | Read secrets from the environment or a vault inside the tool, never in text the model sees |
| **MCP005** bind to 0.0.0.0 | `"0.0.0.0"` or `"::"` for the listener | A local tool server becomes reachable from the network (the "NeighborJack" pattern reported by Backslash Security in 2025; verify) | Bind `127.0.0.1`, or put an authenticating gateway in front |
| **MCP006** verbose errors | `return traceback.format_exc()` or `str(exc)` to the client | Leaks paths, library versions, SQL, secrets in exception text | Log server-side with an error id; return a generic message |

How the lab scanner works: it **parses** the code with Python's `ast` module and walks the tree. It never imports or runs the code. For MCP002 it checks the *whole function*: a join is only acceptable if the function also canonicalizes and checks containment. That is the key idea behind most good SAST rules: look for the dangerous operation **and** the missing guard.

Limits of this approach: it is single-function, name-based and easy to fool (an alias, a helper in another file, a guard that is applied to the wrong variable). Real tools add data-flow (taint) analysis: *a value that came from a tool parameter reaches a dangerous sink without passing a sanitizer*. Know what your tool can and cannot see.

## 4. Scanning for hardcoded secrets

Three techniques, used together:

1. **Known formats (regex):** `AKIA` plus 16 characters for AWS access key ids, `ghp_` plus 36 for GitHub tokens, `sk-` prefixes, PEM `BEGIN PRIVATE KEY` headers, JWT shape. Few false positives.
2. **Generic assignments:** a variable named `api_key`, `secret`, `token`, `password` assigned a quoted literal. Skip obvious placeholders (`<your-key>`, `${ENV}`).
3. **Entropy:** random-looking strings have high Shannon entropy (about 4+ bits per character for base64-like text). Catches unknown formats, but also catches hashes and ids: tune it.

Where to scan: the working tree **and the git history** (a secret removed in the last commit is still in the repo), tool descriptions and manifests, `mcp.json` host configs, `.env` files that were committed by mistake, container layers, CI logs.

Rules for handling a hit: treat it as **real**, revoke and rotate the credential first, then remove it from code, then clean history if needed. Never print the full secret in the CI log (the lab redacts to the first four characters).

**Lab safety:** the lab only contains **FAKE** keys marked `FAKE`. A real pipeline cannot know a key is fake, so the gate treats every hit as real. Prevention: pre-commit hook, push protection on the git host, and the vault pattern from [04 secure-operations](../../04-mcp-security/secure-operations/README.md).

## 5. Identifying vulnerabilities in tool and resource implementations

Read each tool as a tiny API with an attacker on the other side. For every **tool** and every **resource** handler ask:

1. **What are all inputs?** Parameters, resource URIs and templates, prompt arguments, headers, environment, files the tool reads.
2. **Where does each input flow?** To a shell, a file path, a URL, an SQL string, a template, another tool's description, a log line, the model's context.
3. **What guards exist on that path?** Schema validation, allowlists, canonicalization, parameterized queries, output limits.
4. **What can the tool do if it is tricked?** Blast radius: files, network, other tools, credentials it holds.
5. **What does it return?** Untrusted content (web pages, tickets, file contents) goes back into the model: that is the prompt-injection path (MCP06). Return data, not instructions, and bound its size.
6. **Resources specifically:** are URIs mapped to a fixed root? Are templates (`file:///{path}`) canonicalized like file paths? Are subscriptions and listings tenant-filtered (the Asana MCP incident of June 2025 was a tenant-isolation logic flaw)?

## 6. Code review practices and checklist for MCP

Review is where humans catch the context that tools miss (is this tool needed at all?). Use a checklist so every review asks the same questions.

**MCP pull request checklist**

- [ ] **Scope:** Does a new or changed tool do exactly one thing? Could it be split into read and write tools with different scopes?
- [ ] **Description:** Is the text short, honest and free of instructions to the model, URLs, file paths, secrets, hidden characters? Is a description change approved by a code owner?
- [ ] **Schema:** `additionalProperties: false`, types, enums, max lengths, patterns. Is the server validating, not just declaring?
- [ ] **Sinks:** No shell, `eval`, template rendering or dynamic SQL on parameters. Paths canonicalized and contained. URLs allowlisted.
- [ ] **Secrets:** None in code, descriptions, logs, error messages, test fixtures. Per-user credentials, no token passthrough.
- [ ] **Errors:** Generic messages to clients, details in logs with an id.
- [ ] **Output:** Size capped; sensitive fields filtered; untrusted content labelled.
- [ ] **Network:** Bound to localhost or behind a gateway; TLS and auth on remote transports; Origin checked.
- [ ] **Dependencies:** New packages justified, pinned, from the expected registry, audited.
- [ ] **Tests:** A test for the abuse case (traversal, injection, oversized input), not only the happy path.
- [ ] **AI-written code:** Reviewed line by line. AI assistants happily generate `shell=True` and string-built paths (see [CAISP ch4 lesson 01](../../caisp-course/ch4-ai-attacks-and-defenses-devops/01-devops-devsecops-and-ai-in-devops.md)).
- [ ] **Logging:** Tool invocations logged (who, which tool, argument hash), without secrets.

## 7. Optional: Bandit and Semgrep

The lab README has the commands and a `semgrep-mcp-rules.yml` with the same ideas as Semgrep rules. They were **not executed by the repo author**; syntax and flags change, so use the current documentation.

## 8. Interview questions

- *What is the difference between SAST and secret scanning?* SAST finds insecure code patterns and data flows; secret scanning looks for credential formats and high-entropy strings, including in config and history.
- *Why is `os.path.join(base, name)` not safe, and why is `resolve()` alone not enough?* Join keeps absolute paths and `..`; `resolve()` removes `..` and symlinks but you must then **check the result is inside the base**.
- *A scanner reports 40 findings on an MCP server. How do you triage?* Reachability from a tool parameter first, then severity and blast radius; fix sinks reachable from tools; suppress with a justification and an expiry, never silently.

## 9. References

- [Repo: 04 tool-security](../../04-mcp-security/tool-security/README.md) (poisoning scanner, path traversal, SSRF labs)
- Bandit, Semgrep, gitleaks, trufflehog, detect-secrets documentation (verify current versions).
- CVE records for CVE-2025-6514, CVE-2025-53109, CVE-2025-53110 (verify at nvd.nist.gov).
