# Real tool: OWASP Threat Dragon (hedged walkthrough)

> **Hedge.** OWASP Threat Dragon 2.x runs as a desktop app and as a web app (verify current install options at the OWASP project page and GitHub releases). Screens change between versions. Use a fictional system. Only test systems you own or have written permission to test.

## Install

- **Desktop:** download the installer for Windows, macOS or Linux from the GitHub releases page.
- **Web:** run the published container image or build from source, and configure a repository provider (GitHub, GitLab, Bitbucket) for storing models, or use local storage (verify options in the docs).

## Threat model the shop

1. **Create a new threat model**: title, owner, description.
2. **Add a diagram** of type **STRIDE** (other types such as LINDDUN, CIA, DIE, PLOT4ai have been offered; verify).
3. Draw: *Actor* Customer; *Process* Web App and Orders API; *Store* Orders DB; *Data flows* between them; *Trust boundary* around the internal network.
4. Select each element and flow: set properties (protocol, encrypted, public network), then **add threats**: title, type, status (Open, Mitigated, Not applicable), severity, description, mitigation. Use the suggestion feature if your version has one, then edit.
5. Mark elements out of scope **with a reason**.
6. **Save** the JSON and commit it next to the code.
7. **Report:** open the report view and print or save as PDF.

## Check it in CI

Run the [lab validator](../labs/threat-dragon-and-cairis-models/README.md) (`tdmodel.validate`) on the saved JSON. If field names differ in your version, adjust `tdmodel.py`. Fail the build on open High threats or unexplained out-of-scope elements.

## Compare

The CMCPSE course has a [Threat Dragon note](../../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/threat-dragon/README.md) for an MCP architecture with a ready Mermaid DFD to redraw.
