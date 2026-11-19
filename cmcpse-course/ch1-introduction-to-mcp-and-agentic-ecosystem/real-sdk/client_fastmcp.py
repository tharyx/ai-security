"""A client written with the official MCP Python SDK: connect to server_fastmcp.py over stdio.

Install:  python -m pip install mcp
Run:      python client_fastmcp.py

Same exercise as labs/02-connect-local-server: spawn, initialize (the SDK sends initialize and the
initialized notification for you), then list and call. SDK signatures move between releases: if a
call fails, check https://py.sdk.modelcontextprotocol.io for your version.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = Path(__file__).resolve().parent / "server_fastmcp.py"


async def run() -> dict:
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            resources = await session.list_resources()
            prompts = await session.list_prompts()
            added = await session.call_tool("add_note", {"title": "Plan", "text": "Learn MCP security"})
            notes = await session.read_resource("notes://all")
            return {
                "tools": [t.name for t in tools.tools],
                "resources": [str(r.uri) for r in resources.resources],
                "prompts": [p.name for p in prompts.prompts],
                "add_note": added.content[0].text,
                "notes_resource": notes.contents[0].text,
            }


if __name__ == "__main__":
    out = asyncio.run(run())
    for key, value in out.items():
        print(f"{key:15}: {value}")
