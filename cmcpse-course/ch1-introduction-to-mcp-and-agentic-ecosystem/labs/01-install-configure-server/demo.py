"""Talk to server.py by hand: print each raw JSON line sent and received.

Run from the repository root:
    .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/01-install-configure-server/demo.py
"""

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

MESSAGES = [
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},  # too early: before initialize
    {"jsonrpc": "2.0", "id": 2, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}},
]


def main() -> None:
    payload = "".join(json.dumps(m, separators=(",", ":")) + "\n" for m in MESSAGES)
    proc = subprocess.run([sys.executable, "-I", str(HERE / "server.py"), "--config", str(HERE / "config.json")],
                          input=payload, capture_output=True, text=True, timeout=20)
    replies = iter(proc.stdout.splitlines())
    for m in MESSAGES:
        print("->", json.dumps(m, separators=(",", ":")))
        if "id" in m:
            print("<-", next(replies)[:150])
        else:
            print("   (notification: no reply)")
    print("stderr:", proc.stderr.strip())


if __name__ == "__main__":
    main()
