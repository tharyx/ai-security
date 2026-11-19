"""MCP reconnaissance: enumerate endpoints, then turn what an anonymous caller can see into findings.

Works on any *transport* (``(raw, token) -> str``): an in-process server, or the localhost HTTP
client from ``http_transport.py``. It only sends read-only requests plus one malformed
``tools/call`` to see how the server reports errors. Only scan systems you own or may test.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from aisec_lab import load_lab_module

rpc = load_lab_module(__file__, "rpc")

BROAD_NAME_RE = re.compile(r"(shell|exec|eval|run_command|sql|query_any)", re.I)
BROAD_DESC_RE = re.compile(r"(any (shell )?command|any file|arbitrary|any sql|anything)", re.I)
SENSITIVE_URI_RE = re.compile(r"(\.env|secret|credential|id_rsa|passwd|\.aws|token|private)", re.I)
LEAK_RE = re.compile(r"(/srv/|/home/|\\Users\\|Traceback|line \d+|password|passwd|secret|token=|env )", re.I)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
OWASP = {  # OWASP MCP Top 10 (2025, beta) names, verify at source
    "RECON-01": "MCP07 Insufficient Authentication & Authorization",
    "RECON-02": "MCP01 Token Mismanagement & Secret Exposure",
    "RECON-03": "MCP02 Privilege Escalation via Scope Creep",
    "RECON-04": "MCP05 Command Injection & Execution",
    "RECON-05": "MCP10 Context Injection & Over-Sharing",
}


def _finding(fid: str, severity: str, title: str, detail: str) -> dict[str, str]:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "owasp": OWASP[fid]}


def _unconstrained_params(tool: dict[str, Any]) -> list[str]:
    props = tool.get("inputSchema", {}).get("properties", {})
    bad = [n for n, p in props.items()
           if p.get("type") == "string" and not any(k in p for k in ("maxLength", "pattern", "enum"))]
    return bad


def scan_endpoint(address: str, transport: Callable[..., str | None], token: str | None = None) -> dict[str, Any]:
    ep: dict[str, Any] = {"address": address, "auth": "unknown", "tools": [], "resources": [], "prompts": [], "findings": []}
    init = rpc.request(transport, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                 "clientInfo": {"name": "recon", "version": "0"}}, token)
    if init.get("error", {}).get("code") == rpc.UNAUTHORIZED:
        ep["auth"] = "required"
        return ep  # an anonymous scan stops here: that is the good outcome
    ep["auth"] = "none" if token is None else "accepted"
    info = init["result"]
    ep.update(server=info["serverInfo"]["name"], version=info["serverInfo"]["version"], protocol=info["protocolVersion"])
    if token is None:
        ep["findings"].append(_finding("RECON-01", "high", "Unauthenticated MCP endpoint",
                                       "initialize and every list method answered without credentials."))

    tools = rpc.request(transport, "tools/list", token=token).get("result", {}).get("tools", [])
    ep["tools"] = [t["name"] for t in tools]
    ep["resources"] = [r["uri"] for r in rpc.request(transport, "resources/list", token=token).get("result", {}).get("resources", [])]
    ep["prompts"] = [p["name"] for p in rpc.request(transport, "prompts/list", token=token).get("result", {}).get("prompts", [])]

    for t in tools:
        if BROAD_NAME_RE.search(t["name"]) or BROAD_DESC_RE.search(t.get("description", "")):
            ep["findings"].append(_finding("RECON-03", "high", f"Over-broad tool: {t['name']}",
                                           f"Name or description suggests unrestricted power: {t.get('description', '')!r}"))
        bad = _unconstrained_params(t)
        if bad or t.get("inputSchema", {}).get("additionalProperties") is not False:
            ep["findings"].append(_finding("RECON-04", "medium", f"Weak input schema: {t['name']}",
                                           f"unconstrained string params: {bad or 'none'}; additionalProperties not false: "
                                           f"{t.get('inputSchema', {}).get('additionalProperties') is not False}"))
    for uri in ep["resources"]:
        if SENSITIVE_URI_RE.search(uri):
            ep["findings"].append(_finding("RECON-05", "high", f"Sensitive resource exposed: {uri}", "Readable by this caller."))

    if tools:  # one malformed call: how chatty are the errors?
        probe = rpc.request(transport, "tools/call", {"name": tools[0]["name"], "arguments": {"__probe__": 1}}, token)
        msg = probe.get("error", {}).get("message", "")
        probe2 = rpc.request(transport, "tools/call", {"name": tools[0]["name"], "arguments": _bad_args(tools[0])}, token)
        msg2 = probe2.get("error", {}).get("message", "")
        leaked = [m for m in (msg, msg2) if LEAK_RE.search(m)]
        if leaked:
            ep["findings"].append(_finding("RECON-02", "medium", "Verbose error leakage", f"error text: {leaked[0][:160]!r}"))
    ep["findings"].sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return ep


def _bad_args(tool: dict[str, Any]) -> dict[str, Any]:
    """Arguments of the right shape but pointing at something that does not exist."""
    props = tool.get("inputSchema", {}).get("properties", {})
    return {n: ("/definitely/missing/file" if p.get("type") == "string" else 0) for n, p in props.items()}


def scan(network: dict[str, Callable[..., str | None]], tokens: dict[str, str] | None = None) -> dict[str, Any]:
    endpoints = [scan_endpoint(addr, t, (tokens or {}).get(addr)) for addr, t in network.items()]
    counts: dict[str, int] = {}
    for e in endpoints:
        for f in e["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"endpoints": endpoints, "counts": counts}


def render_report(report: dict[str, Any]) -> str:
    lines = ["MCP RECON REPORT", "=" * 60]
    for e in report["endpoints"]:
        head = f"{e['address']}  auth={e['auth']}"
        if "server" in e:
            head += f"  {e['server']} {e['version']} (protocol {e['protocol']})"
        lines.append(head)
        if e["auth"] == "required":
            lines.append("  authentication required: nothing enumerated anonymously")
            continue
        lines.append(f"  tools={e['tools']} resources={e['resources']} prompts={e['prompts']}")
        for f in e["findings"]:
            lines.append(f"  [{f['severity'].upper():6}] {f['id']} {f['title']}  -> {f['owasp']}")
    lines.append("-" * 60)
    lines.append("findings by severity: " + ", ".join(f"{k}={v}" for k, v in sorted(report["counts"].items())) if report["counts"] else "findings by severity: none")
    return "\n".join(lines)
