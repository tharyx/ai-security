# Lab: Auditing and Hardening an Agent Harness Using a Security Audit Plugin

**Course exercise:** "Auditing and Hardening an Agent Harness Using a Security Audit Plugin". Lessons: [05 defending](../../05-defending-computer-use-and-coding-agents.md#6-auditing-and-hardening-a-harness-with-a-security-plugin), [03 case study](../../03-openclaw-case-study.md). Background: [sandboxing](../../../../05-agent-security/sandboxing/README.md).

**Time:** 45 minutes. **Safety:** the configs are JSON files with FAKE values. Nothing is scanned or executed; the plugin only reads the config you give it.

## What it is

`audit_plugin.py` is a small **SecureClaw-style** plugin written for this course. It is not SecureClaw. The real SecureClaw was reported to have about 56 checks based on OWASP ASI and MITRE ATLAS (verify at source). This one has twelve, enough to show the idea: **checks, a weight, a mapping to a framework, a fix, and a score**.

| ID | Check | ASI | ATLAS technique (name; verify IDs at atlas.mitre.org) |
|---|---|---|---|
| SB-01 | Sandbox enabled | ASI05 | Command and Scripting Interpreter (via agent tools) |
| SB-02 | Non-root process | ASI05 | Privilege Escalation |
| SB-03 | Workspace-only file access | ASI02 | Data from Local System |
| NET-01 | Egress allowlist | ASI02 | Exfiltration over Web Services |
| HITL-01 | Approval for destructive actions | ASI09 | AI Agent Tool Invocation |
| HITL-02 | Approval timeout denies | ASI09 | AI Agent Tool Invocation |
| SUP-01 | Skill signature verification | ASI04 | Supply Chain Compromise |
| SUP-02 | Skills pinned, no auto-update | ASI04 | Supply Chain Compromise |
| SEC-01 | Secrets not in env | ASI03 | Unsecured Credentials |
| LOG-01 | Logging on, tamper-evident | ASI10 | Defense Evasion (log tampering) |
| MOD-01 | Model provider allowlist | ASI07 | Supply Chain Compromise (model/service) |
| GW-01 | Gateway loopback and auth | ASI03 | Valid Accounts / Initial Access |

ASI names: ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI07 Insecure Inter-Agent Communication, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. The mapping is a teaching choice; other mappings are defensible.

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/harness-security-audit/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/harness-security-audit -v
```

1. Run the demo on `configs/insecure.json` (score 0) and `configs/hardened.json` (score 100).
2. Copy the insecure config. Fix **only** the sandbox group (`SB-01` to `SB-03`). What is the score? Which ASI risks remain?
3. Add a check of your own (for example "MCP servers pinned by hash") with a weight, an ASI id and a fix.
4. Note the limits: a config audit proves what is **configured**, not what is **running**. Pair it with runtime monitoring.

## Expected output (real run, shortened)

```text
== insecure-demo-harness: score 0/100, grade F ==
  FAIL SB-01   ASI05  sandbox is off: the agent runs with the user's full rights
  ...
  FAIL SEC-01  ASI03  secrets in environment: ['AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY']
  ...
  failures by ASI: {'ASI05': ['SB-01', 'SB-02'], 'ASI02': ['SB-03', 'NET-01'], 'ASI09': ['HITL-01', 'HITL-02'], 'ASI04': ['SUP-01', 'SUP-02'], 'ASI03': ['SEC-01', 'GW-01'], 'ASI10': ['LOG-01'], 'ASI07': ['MOD-01']}

== hardened-demo-harness: score 100/100, grade A ==
  PASS SB-01   ASI05  sandbox enabled
  ...
  PASS GW-01   ASI03  gateway on loopback with auth
```
