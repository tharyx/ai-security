# Lab 03: Observe MCP protocol-level communication

**Course exercise:** "Observing MCP protocol-level communication". This lab builds a small **logging proxy** for stdio. It sits between the client and the server, forwards every line unchanged, and prints one line per JSON-RPC message with a **timestamp**, a **direction** (`C->S` or `S->C`), the message **kind**, the **id** and the **method**. Secrets are redacted **in the log**.

**Time:** 30 minutes. Standard library only.

```text
client  <--stdio-->  proxy.py (logs)  <--stdio-->  server
```

## Why this matters

You cannot defend what you cannot see. Tool descriptions, arguments and results are the whole attack surface of MCP, and they are plain JSON. A protocol-level log is how you debug a broken server, how you investigate an incident, and how you notice a suspicious change.

> Use this only on traffic you own (your lab, your own servers). The log can still contain sensitive arguments and results, so protect the log file. Redaction is best effort, not a guarantee.

## Files

| File | Purpose |
|---|---|
| `proxy.py` | The proxy. Usage: `python proxy.py --log traffic.log -- <server command>` |
| `demo.py` | Runs the lab 02 client through the proxy and prints the log |
| `test_ch1_proxy.py` | 7 tests: redaction (by key and by value shape), classification, formatting, alerts, and an end-to-end run |

## Run

```text
.venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/03-observe-protocol/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/03-observe-protocol -v
```

Real output (long lines cut at about 230 characters; timestamps are UTC):

```text
06:12:54.379  C->S  request      id=1   initialize                 {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lab-client","version":"0.1.0"}}}
06:12:54.574  S->C  response     id=1                              {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"lab-files-server","version":"
06:12:54.574  C->S  notification id=-   notifications/initialized  {"jsonrpc":"2.0","method":"notifications/initialized"}
06:12:54.574  C->S  request      id=2   tools/list                 {"jsonrpc":"2.0","id":2,"method":"tools/list"}
06:12:54.574  S->C  response     id=2                              {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Return the given text unchanged.","inputSchema":{"type":"object","properties":{"text":{"ty
06:12:54.575  C->S  request      id=3   tools/call                 {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":40}}}
06:12:54.575  S->C  response     id=3                              {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"42"}],"isError":false}}
06:12:54.575  C->S  request      id=4   tools/call                 {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"token is [REDACTED]"}}}
06:12:54.575  S->C  response     id=4                              {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"token is [REDACTED]"}],"isError":false}}
06:12:54.575  C->S  request      id=5   tools/call                 {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../secret-outside-root.txt"}}}
06:12:54.575  S->C  response     id=5                              {"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"PermissionError: path is outside the root directory"}],"isError":true}}
```

Notice request 4: the client sent `Bearer abcdef...` and the server received and echoed it **unchanged** (a test proves the proxy does not alter traffic), but the **log** shows `[REDACTED]`.

## What a defender learns from the log

| What you see | What it tells you |
|---|---|
| Direction and order | The lifecycle: `initialize` first, then `initialized`, then operation. Anything else is a bug or an attack. |
| Timestamps | Gaps (a slow tool), bursts (a loop or a flood), and the time of an incident for correlation with other logs. |
| `id` pairs | Every request has a reply. A reply with an unknown id, or a request from the server you never enabled (sampling, roots), is suspicious. |
| `tools/list` result | The exact descriptions the **model** will read. Hidden instructions live here (the proxy adds an `ALERT` line for obvious patterns). **Hash this and compare across sessions to catch a rug pull.** |
| `tools/call` arguments | What the model actually decided to do, which can differ from what the user asked. Arguments pointing at paths, URLs or addresses the user never mentioned are a red flag. |
| `isError: true` results | Probing and attacks that were blocked (path traversal here). A burst of them means someone is testing your server. |
| Notifications such as `tools/list_changed` | The server is changing its tool set mid-session. Re-review. |
| Secrets in arguments or results | A design problem (MCP01). The proxy hides them in the log, but you should also stop sending them. |

Limits: stdio traffic is plain text only to the process that owns the pipes. This proxy sees only what passes through it. It cannot see what the server does to the file system or network on its own, and it cannot decrypt TLS for remote servers (use a gateway built for that). Treat it as **one telemetry source**, together with OS and network logs. The repo's gateway and audit design is in [04-mcp-security](../../../../04-mcp-security/README.md) and [secure-operations](../../../../04-mcp-security/secure-operations/README.md).

## Try it

1. Add a pattern to `SECRET_VALUE` for another token shape you use. Add a test.
2. Write a tiny server whose tool description contains `<IMPORTANT>`. Run it through the proxy: you should see an `ALERT` line.
3. Make the proxy write JSON lines instead of text so a SIEM can ingest them.
4. Count `tools/call` per minute and flag more than 30.

## Questions

1. Why redact in the log but not in the traffic?
2. Why is "log everything" not safe without redaction and access control on the log?
3. Which message lets a server change what the model sees after approval?
