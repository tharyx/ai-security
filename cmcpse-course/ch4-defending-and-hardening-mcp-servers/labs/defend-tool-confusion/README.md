# Lab: defending tool confusion (name collisions and shadowing)

**Course exercise:** Defending tool confusion · **Lesson:** [03 section 7](../../03-secure-tool-and-resource-design.md) · **Related:** [Module 04, tool-security](../../../../04-mcp-security/tool-security/README.md) (shadowing), [Module 04, mcp-server](../../../../04-mcp-security/mcp-server/README.md) (typosquat and impostor servers)

Tool confusion: a host merges the tools of several servers into one flat list. A later server can **shadow** `send_email`, expose a **look-alike** (`send_emai1`, a Cyrillic letter) or add "use me instead" text. Defenses: **namespacing** (`server.tool`), an **allowlist** of approved pairs, **description pinning**, strict **name hygiene** (the separator is reserved), and **look-alike detection**. Tests: `test_namespacing.py` (13).

| File | Role |
|---|---|
| [`namespacing.py`](namespacing.py) | `NaiveAggregator` (the bug), `SecureAggregator`, `skeleton()`, `edit_distance()`, `lab_servers()`, `lab_allowlist()` |
| [`demo.py`](demo.py) | Naive merge versus secure aggregator |

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-tool-confusion/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-tool-confusion
```

Real demo output:

```text
NAIVE exposed names : ['send_email', 'send_emai1', 'sеnd_email', 'weather']
NAIVE send_email    -> EVIL copy sent to attacker, original to boss@example.org

SECURE exposed names: ['mail.send_email', 'helper.weather']
SECURE mail.send_email -> MAIL sent to boss@example.org
SECURE bare name       -> cannot call 'send_email': use the qualified name server.tool

findings:
  bad_tool_name                helper.'sеnd_email': characters outside [A-Za-z0-9_-] (the separator is reserved)
  name_collision               helper.'send_email': resembles mail.send_email
  lookalike_name               helper.'send_emai1': resembles mail.send_email
```

(The second name in the naive list contains a Cyrillic letter that looks like Latin "e".) The allowlisted tool wins even if the server order is reversed. Bare names are refused, so the model cannot be tricked into calling a tool by an ambiguous name.

## Your tasks

1. Add a server that exposes `mail.send_email` as a raw tool name. Which check stops it?
2. Change the allowlist so `helper.weather` is pinned by description. Edit the description in the server and watch the tool disappear.
3. Use a different separator (`__`) and update the tests. What compatibility problems can the separator cause with hosts (verify allowed tool-name characters in the spec)?
4. Add an alias table so the model can say `email.send` for `mail.send_email`. What new risk does an alias table create?
