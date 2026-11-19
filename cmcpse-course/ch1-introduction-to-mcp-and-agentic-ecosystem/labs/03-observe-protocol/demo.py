"""Run the lab 02 client through the logging proxy and print what the proxy saw.

Run from the repository root:
    .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/03-observe-protocol/demo.py
"""

import importlib.util
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABS = HERE.parent
spec = importlib.util.spec_from_file_location("lab2_client", LABS / "02-connect-local-server" / "client.py")
client_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_mod)

SERVER = LABS / "01-install-configure-server" / "server.py"
CONFIG = LABS / "01-install-configure-server" / "config.json"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "traffic.log"
        cmd = [sys.executable, "-I", str(HERE / "proxy.py"), "--log", str(log_path), "--",
               sys.executable, "-I", str(SERVER), "--config", str(CONFIG)]
        with client_mod.MCPClient(cmd) as client:
            client.initialize()
            client.list_tools()
            client.call_tool("add", {"a": 2, "b": 40})
            # A secret travels in a tool argument. The server gets it; the LOG does not keep it.
            client.call_tool("echo", {"text": "token is Bearer abcdef1234567890abcdef"})
            client.call_tool("read_file", {"path": "../secret-outside-root.txt"})
        print(log_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
