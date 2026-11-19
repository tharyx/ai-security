"""Connect to the lab 01 server, negotiate, list tools, call tools.

Run from the repository root:
    .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/02-connect-local-server/demo.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from client import MCPClient, MCPError, result_text  # noqa: E402

SERVER = HERE.parent / "01-install-configure-server" / "server.py"
CONFIG = HERE.parent / "01-install-configure-server" / "config.json"


def main() -> None:
    cmd = [sys.executable, "-I", str(SERVER), "--config", str(CONFIG)]
    with MCPClient(cmd) as client:
        client.initialize()
        print(f"server      : {client.server_info}")
        print(f"protocol    : {client.protocol_version}")
        print(f"capabilities: {client.server_capabilities}")
        print("tools       :", ", ".join(t["name"] for t in client.list_tools()))
        print("add(2, 40)  :", result_text(client.call_tool("add", {"a": 2, "b": 40})))
        print("list_files  :", result_text(client.call_tool("list_files")).replace("\n", ", "))
        print("read_file   :", result_text(client.call_tool("read_file", {"path": "hello.txt"})).splitlines()[0])
        bad = client.call_tool("read_file", {"path": "../secret-outside-root.txt"})
        print("traversal   :", f"isError={bad['isError']}", result_text(bad))
        try:
            client.call_tool("delete_everything")
        except MCPError as exc:
            print("unknown tool:", exc)


if __name__ == "__main__":
    main()
