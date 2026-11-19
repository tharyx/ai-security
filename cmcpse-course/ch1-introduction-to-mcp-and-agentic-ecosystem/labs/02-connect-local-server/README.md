# Lab 02: Connect to a local MCP server

**Course exercise:** "Connect to a local MCP server". Here you build the **client** half: spawn the server from lab 01, do the `initialize` handshake, negotiate capabilities, list tools and call them.

**Time:** 30 minutes. Standard library only.

## Why this matters

The client lives inside every host. It is the place that should check the protocol version, only use negotiated capabilities, and decide how to treat errors. A client that blindly trusts the server is how a rug pull or a downgrade slips through.

## Files

| File | Purpose |
|---|---|
| `client.py` | `MCPClient`: spawns a command, sends/reads newline-delimited JSON, runs the lifecycle |
| `demo.py` | Connects to the lab 01 server and prints each step |
| `test_ch1_connect_client.py` | 7 tests: handshake, tools, error kinds, lifecycle order, version mismatch, dead server |

## Run

```text
.venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/02-connect-local-server/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/02-connect-local-server -v
```

Real output:

```text
server      : {'name': 'lab-files-server', 'version': '0.1.0'}
protocol    : 2025-06-18
capabilities: {'tools': {'listChanged': False}}
tools       : echo, add, list_files, read_file
add(2, 40)  : 42
list_files  : hello.txt
read_file   : Hello from the sandbox directory.
traversal   : isError=True PermissionError: path is outside the root directory
unknown tool: JSON-RPC error -32602: Unknown tool: delete_everything
```

## What to notice

- **Order matters:** `initialize` request, then `notifications/initialized`, then everything else.
- **Capability negotiation:** the client records `server_capabilities` and refuses `list_tools()` if `tools` is missing (tested).
- **Version negotiation:** the client asks for `2025-06-18`. If the server answers with something else, this client disconnects. A real client may support several versions, but it should never continue with one it cannot speak.
- **Two error kinds:** `MCPError` is a protocol error (unknown tool). A tool failure arrives as normal data with `isError: true`, so the *model* can read it.
- **Server-initiated requests:** if the server sends a request for a feature the client never advertised (sampling, roots), the client answers `-32601`. Real hosts must also keep a human in the loop for sampling and elicitation.
- **Shutdown:** closing stdin is the polite stop signal on stdio.

## Try it

1. Change `CLIENT_VERSION` to `2024-11-05`. The server accepts it (it supports that version) and the handshake still works.
2. Remove the `notifications/initialized` call. Does this server still answer `tools/list`? (It does: it only checks that `initialize` happened. A stricter server could refuse. What would you prefer, and why?)
3. Point the client at a command that does not speak MCP (`python -c "print('hello')"`). What error do you get?

## Questions

1. Why should the client check `protocolVersion` in the reply and not assume it?
2. What would a malicious server gain by advertising capabilities it will not honor?
3. Why is "one client per server" a security feature?
