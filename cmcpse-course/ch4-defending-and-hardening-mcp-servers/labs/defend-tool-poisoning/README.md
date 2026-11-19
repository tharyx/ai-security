# Lab: defending tool poisoning

**Course exercise:** Defending tool poisoning · **Lesson:** [03 sections 6 and 7](../../03-secure-tool-and-resource-design.md) · **Deeper scanner:** [Module 04, tool-security](../../../../04-mcp-security/tool-security/README.md) (`tool_scanner.py`)

Tool poisoning hides instructions for the model in tool metadata. This lab scans the **whole definition** (name, description, annotations, every schema string including property names, enums, defaults and examples), blocks high-severity findings, **sanitizes** what remains (Unicode normalised, invisible characters stripped, lengths capped, defaults and examples dropped), and lets a host show a **human-reviewed description** instead of the server text. Tests: `test_poison_defense.py` (13). The fixtures are synthetic and harmless text.

| File | Role |
|---|---|
| [`poison_defense.py`](poison_defense.py) | `walk_text`, `scan_tool`, `decide`, `sanitize_tool`, `ToolGate`, `fixtures()` (honest, classic, parameter, default, unicode, shadow, enum poisoning) |
| [`demo.py`](demo.py) | Gate a catalogue of eight tools |

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-tool-poisoning/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/defend-tool-poisoning
```

Real demo output:

```text
ALLOW  add              
BLOCK  add_pro          model_directive@description; call_ordering@description; sensitive_path@description
BLOCK  weather          sensitive_path@inputSchema.properties.city.description
BLOCK  lookup           model_directive@inputSchema.properties.q.default
BLOCK  greet            hidden_unicode@description
BLOCK  calendar_helper  exfil_channel@description; references_other_tool@description
BLOCK  mode             model_directive@inputSchema.properties.m.enum[2]; references_other_tool@description
ALLOW  send_email       

the model receives: ['add', 'send_email']
```

A test shows a **paraphrased** attack that the regexes miss. That is intended: scanning is one layer; pinning, review and gateway inspection are the others. A tool named like a common word (`add`) can create false "references other tool" findings: tune it.

## Your tasks

1. Add a rule for a Base64 blob longer than 60 characters in a default (a medium finding exists; make it high when it decodes to text with instruction words).
2. Add a fixture with an instruction hidden in an HTML comment inside the description. Detect it and sanitize it.
3. Write the `reviewed` description for `calendar_helper` that a human would approve, and show that the gate uses it.
4. Run the scanner on the tools of a real MCP server you use (read-only) and report the false positives.
