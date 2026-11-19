# Lab 01: Install and configure a Python MCP-style server from scratch

**Course exercise:** "Install and configure a Python-based MCP server from scratch". The course does this in its browser lab with real tooling. This offline twin shows what such a server *is*: a loop that reads JSON-RPC lines from stdin and writes replies to stdout, driven by a config file.

**Time:** 30 minutes. Nothing to install: Python standard library only. (For the official SDK, see [`../../real-sdk/`](../../real-sdk/README.md).)

## Why this matters

A stdio MCP server is just a program the host launches. Understanding the three moving parts (**config, process, protocol**) tells you where to look for risk: *who writes the config, what the process can touch, and what the protocol lets a client ask for.*

## Files

| File | Purpose |
|---|---|
| `server.py` | The server: JSON-RPC 2.0 over stdio, tools `echo`, `add`, `list_files`, `read_file` |
| `config.json` | `name`, `version`, `tools_enabled` (which tools exist) and `root_dir` (where files may be read) |
| `sandbox/hello.txt` | The only folder `read_file` may reach |
| `secret-outside-root.txt` | A canary outside the root. If any tool returns it, the path check is broken |
| `demo.py` | Sends a few raw messages and prints replies |
| `test_ch1_install_server.py` | Spawns the server with `python -I` and exchanges `initialize` / `tools/list` over stdin/stdout |

## Steps

1. Read `config.json`. Remove `read_file` from `tools_enabled`, restart, and list tools: it is gone, and calling it gives `Unknown tool`. **Configuration is your first access control.**
2. Run the demo:

   ```text
   .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server/demo.py
   ```

   Real output (shortened lines):

   ```text
   -> {"jsonrpc":"2.0","id":1,"method":"tools/list"}
   <- {"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Server not initialized"}}
   -> {"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}
   <- {"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"lab-files-server
   -> {"jsonrpc":"2.0","method":"notifications/initialized"}
      (notification: no reply)
   -> {"jsonrpc":"2.0","id":3,"method":"tools/list"}
   <- {"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"echo","description":"Return the given text unchanged.",...
   -> {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
   <- {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"hi"}],"isError":false}}
   stderr: [lab-files-server] started, tools=['echo', 'add', 'list_files', 'read_file'], root=...\sandbox
   ```

3. Run it by hand in a terminal and type JSON lines (end with Ctrl+Z then Enter on Windows, Ctrl+D elsewhere):

   ```text
   .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server/server.py --config cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server/config.json
   ```

4. Run the tests:

   ```text
   .venv/Scripts/python -m pytest cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server -v
   ```

## What to notice (security)

- **stdout is the protocol.** The startup message goes to **stderr**. A stray `print()` would corrupt the stream. A test checks this.
- **`-I` (isolated mode).** The tests start Python with `-I` so environment variables like `PYTHONPATH` and the current folder cannot inject modules. Good habit for any server you launch.
- **Path containment.** `read_file` resolves the path and checks it is inside `root_dir`. `..`, absolute paths and symlinks that leave the root are refused (tested). Roots in real MCP are only hints: this check is the actual control.
- **Validation errors are tool results** (`isError: true`), unknown tools are protocol errors.
- **Lifecycle is enforced.** Calls before `initialize` get `-32600`.

## Try to break it

- Add `"tools_enabled": ["nope"]` to the config. What happens and why is failing at startup good?
- Create a symlink inside `sandbox/` pointing outside (on Windows this may need admin rights). Does `read_file` follow it?
- Send a 1 MB string to `echo`. Where would you add a size limit? (Lab 04 does this with `maxLength`.)

## Questions

1. Why does a notification get no reply?
2. Why is `root_dir` resolved relative to the config file and not the current directory?
3. What would change if this server also kept an API key in `config.json`? (See MCP01 in [secure-operations](../../../../04-mcp-security/secure-operations/README.md).)
