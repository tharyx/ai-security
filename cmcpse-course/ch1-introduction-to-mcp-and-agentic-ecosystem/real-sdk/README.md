# Real SDK versions (optional): FastMCP server and client, and MCP Inspector

The offline labs teach the protocol with plain Python. This folder does the same exercises with the **official MCP Python SDK**, which is what you will use in practice and (likely) in the course lab. Nothing here is needed for the labs' tests.

| Script | Same as | What it does |
|---|---|---|
| [`server_fastmcp.py`](server_fastmcp.py) | [lab 01](../labs/01-install-configure-server/README.md) and [lab 04](../labs/04-build-server-tools-resources/README.md) | Notes server with 2 tools, 2 resources, 1 prompt, written with decorators |
| [`client_fastmcp.py`](client_fastmcp.py) | [lab 02](../labs/02-connect-local-server/README.md) | Spawns the server over stdio, initializes, lists and calls |
| [`test_ch1_real_sdk.py`](test_ch1_real_sdk.py) | | Runs the client against the server. **Skipped automatically if `mcp` is not installed** |

## Install

```text
.venv/Scripts/python -m pip install mcp
```

Version note, checked while writing this (Nov 2026): `pip install mcp` gave **2.3.0**, where the high-level class is called `MCPServer` (`mcp.server.mcpserver`). In the **1.x** line the same class is `FastMCP` (`mcp.server.fastmcp`). The server script tries both imports. The client calls (`stdio_client`, `ClientSession`, `initialize`, `list_tools`, `call_tool`, `read_resource`) worked unchanged on 2.3.0. SDK names and signatures move between releases: **verify at <https://py.sdk.modelcontextprotocol.io>** and pin a version (`pip install "mcp==2.3.0"` or `"mcp<2"`) in real projects.

## Run

```text
.venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/real-sdk/client_fastmcp.py
.venv/Scripts/python -m pytest cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/real-sdk
```

Real output (mcp 2.3.0):

```text
tools          : ['add_note', 'search_notes']
resources      : ['notes://all', 'docs://about']
prompts        : ['summarize_notes']
add_note       : Stored note 'Plan'. Total notes: 2.
notes_resource : [
  {
    "title": "Welcome",
    "text": "This is the first note."
  },
  {
    "title": "Plan",
    "text": "Learn MCP security"
  }
]
```

## What the SDK does for you, and what it does not

| The SDK handles | You still own |
|---|---|
| JSON-RPC framing, ids, errors | Validating values (length, ranges, allowed paths). Type hints become a schema, but they are not business rules. |
| `initialize`, version and capability negotiation | Which servers you start and trust (pin, review) |
| Tool, resource and prompt listing and schemas | What each tool is allowed to do (least privilege, no shell, no secrets in output) |
| stdio and HTTP transports | Authentication for HTTP, binding to `127.0.0.1`, TLS, `Origin` checks |

In `server_fastmcp.py` the length checks are written **by hand** inside `add_note` for that reason. Compare with `validate()` in the offline lab.

## Inspect with MCP Inspector (hedged)

**MCP Inspector** is the official visual tool to connect to a server, list tools, call them and watch messages. It needs Node.js. Commands change between versions: check the project page (<https://github.com/modelcontextprotocol/inspector>) before relying on these.

```text
# typical form (verify at source): runs the Inspector and starts your server as a stdio child
npx @modelcontextprotocol/inspector python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/real-sdk/server_fastmcp.py

# older SDK versions also had a helper (verify it exists in your version):
# mcp dev cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/real-sdk/server_fastmcp.py
```

The Inspector prints a local URL (and, in recent versions, a session token). Open it in a browser, **Connect**, then use the Tools, Resources and Prompts tabs and the History pane to see each JSON-RPC message. Compare the history with the proxy log from [lab 03](../labs/03-observe-protocol/README.md).

**Security warning: the Inspector itself had a critical vulnerability.** **CVE-2025-49596** (reported by Oligo Security, 2025): versions before **0.14.1** had no authentication between the Inspector's web UI and its local proxy, so a malicious web page could reach the proxy and cause **remote code execution** on the developer's machine. Fixed in 0.14.1, which added a session token and origin checks. So:

- **Update to the latest version** every time (`npx` may cache an old one: pin and refresh).
- **Keep it on localhost.** Never bind it to `0.0.0.0` and never expose its ports to a network or tunnel.
- **Keep authentication on.** Do not disable the proxy auth option for convenience.
- **Avoid browsing untrusted web sites** in the same browser while the Inspector is running: the CVE was exploitable from a web page.
- **Only start servers you trust** from it: the Inspector can launch any command you give it.

Lesson: developer tools around MCP are part of your attack surface. This is covered again in Chapter 5 (DevSecOps).

## Try it

1. Connect the Inspector to the server and send `add_note` with a 60-character title. Compare the error message with the offline lab.
2. Run the server over HTTP (see the SDK docs for `run` options in your version). Keep it on `127.0.0.1`. What would you need before exposing it? (Authentication, TLS, `Origin` checks.)
3. Write a second tool that reads a file, and apply the path check from lab 01.
