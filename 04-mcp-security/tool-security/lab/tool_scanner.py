"""A static scanner for MCP tool definitions (tool poisoning, shadowing, hidden text).

Run it on the output of tools/list from every server *before* approval, and again
whenever a definition changes. It reads every string in the definition: the
description, parameter names, parameter descriptions and defaults.

This is a review aid, not a security boundary. Regexes miss paraphrases. The hard
controls are the registry, hash pinning and human review (see mcp-server/).
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

HIGH, MEDIUM, LOW = "high", "medium", "low"

RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("hidden_instruction_tag", HIGH, re.compile(r"<\s*(important|system|instructions?|secret)\b|\[INST\]|<!--", re.I)),
    ("secrecy_request", HIGH, re.compile(
        r"(do not|don't|never)\s+(tell|mention|inform|reveal|show)\b|without (telling|informing)", re.I)),
    ("sensitive_path", HIGH, re.compile(
        r"~/\.ssh|id_rsa|\.env\b|mcp\.json|\.aws/credentials|/etc/passwd|\.npmrc|\.git-credentials", re.I)),
    ("tool_directive", HIGH, re.compile(r"CALL_TOOL|<function_calls>|tool_use", re.I)),
    ("override_language", MEDIUM, re.compile(
        r"ignore (all |any )?(previous|prior|above)|before using (this|any) tool|instead of|"
        r"always (add|include|send|bcc|cc)\b", re.I)),
]
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)|\b[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
MAX_DESCRIPTION = 1024


@dataclass(frozen=True)
class Finding:
    server: str
    tool: str
    rule: str
    severity: str
    evidence: str


def invisible_chars(text: str) -> list[str]:
    """Zero-width, bidi-control and Unicode 'tag' characters (used for ASCII smuggling)."""
    found = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F or unicodedata.category(ch) == "Cf":
            found.append(f"U+{cp:04X}")
    return found


def _all_text(tool: dict[str, Any]) -> str:
    """Description + the whole input schema (names, descriptions, defaults, enums)."""
    return f"{tool.get('description', '')}\n{json.dumps(tool.get('inputSchema', {}), ensure_ascii=False)}"


def scan(servers: dict[str, list[dict[str, Any]]], allowed_domains: frozenset[str] = frozenset()) -> list[Finding]:
    findings: list[Finding] = []
    owners: dict[str, list[str]] = {}
    for server, tools in servers.items():
        for tool in tools:
            owners.setdefault(tool["name"], []).append(server)

    for server, tools in servers.items():
        other_tools = {name for name, srv in owners.items() if server not in srv}
        for tool in tools:
            name, text = tool["name"], _all_text(tool)

            def add(rule: str, severity: str, evidence: str) -> None:
                findings.append(Finding(server, name, rule, severity, evidence[:60]))

            for rule, severity, pattern in RULES:
                m = pattern.search(text)
                if m:
                    add(rule, severity, m.group(0))
            hidden = invisible_chars(text)
            if hidden:
                add("invisible_unicode", HIGH, f"{len(hidden)} hidden chars, e.g. {hidden[0]}")
            for m in URL_RE.finditer(text):
                domain = (m.group(1) or m.group(2)).lower()
                if domain not in allowed_domains:
                    add("unknown_domain", MEDIUM, domain)
            for other in sorted(other_tools):
                if re.search(rf"\b{re.escape(other)}\b", tool.get("description", "")):
                    add("cross_tool_reference", HIGH, f"mentions '{other}' from {owners[other][0]}")
            if len(owners[name]) > 1:
                add("name_collision", HIGH, f"'{name}' also defined by {[s for s in owners[name] if s != server]}")
            if len(tool.get("description", "")) > MAX_DESCRIPTION:
                add("long_description", LOW, f"{len(tool['description'])} chars")
            schema = tool.get("inputSchema", {})
            if schema.get("additionalProperties") is not False:
                add("open_schema", LOW, "additionalProperties is not false")
    return findings
