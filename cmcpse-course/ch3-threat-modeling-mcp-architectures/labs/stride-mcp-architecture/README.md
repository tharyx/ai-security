# Lab: STRIDE for an MCP architecture

**Course exercise:** Apply STRIDE to a provided MCP architecture and document findings.
**Runs offline.** Needs `pyyaml` (already a repo dependency). Tests: `test_stride_mcp.py` (13 tests).

| File | Role |
|---|---|
| [`mcp_architecture.yaml`](mcp_architecture.yaml) | The provided architecture: host, three local servers (files and git over stdio; db over HTTP on 127.0.0.1), one remote OAuth server (crm) with its IdP, a registry, 3 stores, 18 flows, 5 trust zones |
| [`mcp_threat_library.yaml`](mcp_threat_library.yaml) | 27 reusable MCP threats with STRIDE letter, element kinds, tags, OWASP MCP and ASI ids, mitigating controls and 0-9 factors |
| [`stride_mcp.py`](stride_mcp.py) | The tool: `validate()`, `crossings()`, `find_threats()`, `to_markdown/csv/mermaid()` |
| [`findings-template.md`](findings-template.md) | Where you document your decisions |
| [`demo.py`](demo.py) | Prints a summary and the interesting findings |

## Run

```bash
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/demo.py
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/stride_mcp.py --format csv
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture/stride_mcp.py --mermaid
python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stride-mcp-architecture
```

Real demo output (trimmed):

```text
DFD problems: none
Flows that cross a trust boundary: F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14

62 findings: 56 open, 6 mitigated
By STRIDE: S=4, T=25, R=3, I=10, D=14, E=6
```

## How the tool decides

* **Per element:** a threat applies when its STRIDE letter is allowed for the element type (entity S,R; process STRIDE; store TRID; flow TID), the type is in `applies_to`, and the element has one of the `when_tags`.
* **Per crossing:** flows whose ends are in different zones are crossings. `boundary_only` threats (injection in results) are generated only for them.
* **Mitigated or open:** a finding is `mitigated` if at least one control from `mitigated_by` is listed on the element. That is a hint, not proof. Look at `missing_controls`.

## Your task

1. Run the tool and read all 62 findings.
2. For at least 15 findings fill the [`findings-template.md`](findings-template.md): decision (confirm, false positive, accept, re-scope), reason, owner, and the test that proves the control.
3. Add three threats of your own that the library does not have (hints: a prompt or resource exposed by a server; sampling requests from a malicious server; elicitation used for phishing).
4. Edit the YAML: add `tool_pinning` and `description_scanning` to the host, and an `ai_firewall` control. Re-run and note which findings become mitigated.

## Limits

The library is small and generic. It cannot reason about chains of calls or about your business logic. It is a teaching tool for the method, not a scanner.
