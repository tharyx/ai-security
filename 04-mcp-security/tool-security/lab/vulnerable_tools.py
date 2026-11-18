"""A deliberately vulnerable MCP tool server: read_file, fetch_url and run_command.

These are the three tools that appear in almost every "my first MCP server"
tutorial, written the quick way. The server also has a small "summarize this URL"
loop that shows how a tool *result* can hijack the next tool call.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the whole scorecard from the repository root:
    python 04-mcp-security/tool-security/lab/demo.py
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from aisec_lab import LLM, get_llm


class VulnerableToolServer:
    def __init__(self, root: str | os.PathLike, network: Any, shell: Any, llm: LLM | None = None) -> None:
        self.root = str(root)
        self.network = network
        self.shell = shell
        self.llm = llm or get_llm()
        self.tools: dict[str, Callable[..., str]] = {
            "read_file": self.read_file,
            "fetch_url": self.fetch_url,
            "run_command": self.run_command,
        }

    def call(self, name: str, args: dict[str, Any]) -> str:
        # VULN 1: no schema. Arguments are passed straight through as **kwargs.
        return self.tools[name](**args)

    def read_file(self, path: str) -> str:
        # VULN 2: os.path.join + open. "../" walks out of the root, and an absolute
        # path makes os.path.join throw the root away completely.
        with open(os.path.join(self.root, path), encoding="utf-8") as f:
            return f.read()  # VULN 3: no size limit

    def fetch_url(self, url: str) -> str:
        # VULN 4: any scheme, any host, any IP (cloud metadata, localhost), redirects followed.
        return self.network.fetch(url, follow_redirects=True)["body"]

    def run_command(self, command: str) -> str:
        # VULN 5: a free-form string handed to a shell. ; && | $( ) all become code.
        return self.shell.run(command)

    def summarize_url(self, url: str) -> str:
        page = self.fetch_url(url)
        # VULN 6: the tool result goes into the prompt as if it were trusted, and
        # whatever tool call the model proposes next is executed.
        messages = [
            {"role": "system", "content": "Summarize the page for the user."},
            {"role": "user", "content": f"<document>{page}</document>"},
        ]
        output = self.llm.complete(messages)
        try:
            call = json.loads(output)
        except json.JSONDecodeError:
            return output
        if isinstance(call, dict) and call.get("tool") in self.tools:
            return self.call(call["tool"], call.get("args", {}))
        return output


def half_fixed_is_inside(root: str, path: str) -> bool:
    """A common "fix" that is still wrong: a string prefix check.

    /srv/workspace_secrets starts with /srv/workspace, so it passes. A prefix check
    like this was at the heart of CVE-2025-53110 in a reference Filesystem MCP server.
    """
    return os.path.abspath(os.path.join(root, path)).startswith(os.path.abspath(root))
