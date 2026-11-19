"""Use the notes server through the lab 02 client: tools, resources, a prompt, and bad input.

Run from the repository root:
    .venv/Scripts/python cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/labs/04-build-server-tools-resources/demo.py
"""

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lab2_client", HERE.parent / "02-connect-local-server" / "client.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)


def main() -> None:
    with cm.MCPClient([sys.executable, "-I", str(HERE / "notes_server.py")]) as c:
        c.initialize()
        print("capabilities :", sorted(c.server_capabilities))
        print("tools        :", [t["name"] for t in c.list_tools()])
        print("resources    :", [r["uri"] for r in c.request("resources/list")["resources"]])
        print("prompts      :", [p["name"] for p in c.request("prompts/list")["prompts"]])
        print("add_note     :", cm.result_text(c.call_tool("add_note", {"title": "Plan", "text": "Learn MCP security"})))
        print("search_notes :", cm.result_text(c.call_tool("search_notes", {"query": "mcp"})))
        notes = c.request("resources/read", {"uri": "notes://all"})["contents"][0]
        print("notes://all  :", json.dumps(json.loads(notes["text"])))
        bad = c.call_tool("add_note", {"title": "x" * 80, "text": "too long title"})
        print("bad input    :", f"isError={bad['isError']}", cm.result_text(bad))
        try:
            c.request("resources/read", {"uri": "file:///etc/passwd"})
        except cm.MCPError as exc:
            print("bad resource :", exc)
        prompt = c.request("prompts/get", {"name": "summarize_notes", "arguments": {"style": "brief"}})
        print("prompt       :", prompt["messages"][0]["content"]["text"][:70] + "...")


if __name__ == "__main__":
    main()
