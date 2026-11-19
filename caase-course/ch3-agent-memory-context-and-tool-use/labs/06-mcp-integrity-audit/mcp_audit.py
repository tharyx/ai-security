"""Auditing an agent's MCP server connections for data integrity.

Part A, config audit: reads a Hermes-style MCP server list (an *illustrative* YAML shape, not the
real Hermes schema; see the README guide) and reports pinned versions, tool-definition hashes,
transport, authentication, secrets, allowlists and bind addresses. ``check_definitions`` compares the
tool definitions a server serves *now* with the hashes you pinned (rug-pull / drift detection).

Part B, response integrity: a server signs (HMAC) each result together with the tool name, the
arguments and a nonce. The client verifies the signature, rejects replays, and keeps a hash-chained
log so later tampering with stored results is detectable. A gateway can alternatively record a plain
SHA-256 of each result ("hashed" mode) which detects changes but not who made them.

Keys and tokens are fake.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

import yaml

SERVER_KEY = b"FAKE-server-signing-key"


# ---- Part A: config audit ------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    server: str
    message: str


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def tool_hash(tool_def: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(tool_def).encode()).hexdigest()


def _unpinned(server: dict) -> bool:
    version = str(server.get("version", ""))
    args = " ".join(str(a) for a in server.get("args", []))
    spec = re.search(r"@[\w./-]+@([\w.\-]+)", args) or re.search(r"==([\w.\-]+)", args)
    return (not version or version in ("latest", "*") or "latest" in args or
            (server.get("command") in ("npx", "uvx", "pipx") and not spec))


def audit_config(text: str) -> list[Finding]:
    cfg = yaml.safe_load(text) or {}
    out: list[Finding] = []
    for s in cfg.get("mcp_servers", []):
        name, transport = s.get("name", "?"), s.get("transport", "stdio")
        url = str(s.get("url", ""))
        remote = transport in ("http", "streamable-http", "sse")

        def add(rule, sev, msg):
            out.append(Finding(rule, sev, name, msg))

        if _unpinned(s):
            add("AUD-01", "high", "package/version not pinned (use an exact version and an integrity hash)")
        elif not s.get("integrity"):
            add("AUD-01", "medium", "version pinned but no package integrity hash recorded")
        if not s.get("tool_hashes"):
            add("AUD-02", "high", "tool definitions are not hash-pinned (rug-pull blind spot)")
        if remote and url.startswith("http://") and not re.match(r"http://(127\.0\.0\.1|localhost|\[::1\])", url):
            add("AUD-03", "high", "remote server over plain HTTP")
        if remote and not s.get("auth"):
            add("AUD-04", "high", "remote server without authentication")
        for k, v in (s.get("env") or {}).items():
            if re.search(r"(KEY|TOKEN|SECRET|PASSWORD)", k, re.I) and not str(v).startswith("${"):
                add("AUD-05", "critical", f"literal secret in env {k} (reference a secret store instead)")
        allow = s.get("tools_allow")
        if not allow or "*" in allow:
            add("AUD-06", "medium", "no tool allowlist (every tool the server exposes is reachable)")
        if "0.0.0.0" in url or str(s.get("bind", "")) == "0.0.0.0":
            add("AUD-07", "high", "bound to all interfaces")
        if transport == "sse":
            add("AUD-08", "low", "deprecated HTTP+SSE transport; move to Streamable HTTP")
    return out


def check_definitions(server: dict, live_tools: list[dict]) -> list[Finding]:
    """Compare live tool definitions with pinned hashes: changed, new and vanished tools."""
    pinned = server.get("tool_hashes") or {}
    name = server.get("name", "?")
    live = {t["name"]: tool_hash(t) for t in live_tools}
    out = []
    for t, h in live.items():
        if t not in pinned:
            out.append(Finding("AUD-09", "high", name, f"new tool not in the pinned set: {t}"))
        elif pinned[t] != h:
            out.append(Finding("AUD-09", "critical", name, f"definition of {t} changed since it was pinned"))
    for t in pinned:
        if t not in live:
            out.append(Finding("AUD-09", "low", name, f"pinned tool no longer served: {t}"))
    return out


# ---- Part B: response integrity ------------------------------------------------------
def sign_result(key: bytes, server: str, tool: str, args: dict, result: str, nonce: str) -> str:
    msg = canonical({"server": server, "tool": tool, "args": args, "result": result, "nonce": nonce})
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


class SigningServer:
    """A server that signs every result; ``tamper`` simulates a man-in-the-middle or a compromised proxy."""

    def __init__(self, name: str, key: bytes = SERVER_KEY):
        self.name, self.key, self.counter = name, key, 0

    def call(self, tool: str, args: dict, result: str) -> dict:
        self.counter += 1
        nonce = f"{self.name}-{self.counter}"
        return {"server": self.name, "tool": tool, "args": args, "result": result, "nonce": nonce,
                "sig": sign_result(self.key, self.name, tool, args, result, nonce)}


@dataclass
class VerifyingClient:
    key: bytes = SERVER_KEY
    seen: set[str] = field(default_factory=set)
    chain: list[dict] = field(default_factory=list)

    def accept(self, msg: dict) -> tuple[bool, str]:
        expected = sign_result(self.key, msg["server"], msg["tool"], msg["args"], msg["result"], msg["nonce"])
        if not hmac.compare_digest(expected, msg.get("sig", "")):
            return False, "bad signature (result or arguments altered, or wrong key)"
        if msg["nonce"] in self.seen:
            return False, "replayed message"
        self.seen.add(msg["nonce"])
        prev = self.chain[-1]["link"] if self.chain else "genesis"
        link = hashlib.sha256((prev + canonical(msg)).encode()).hexdigest()
        self.chain.append({"msg": msg, "link": link})
        return True, "ok"

    def verify_chain(self) -> int | None:
        """Return the index of the first tampered log entry, or None if the stored log is intact."""
        prev = "genesis"
        for i, e in enumerate(self.chain):
            if hashlib.sha256((prev + canonical(e["msg"])).encode()).hexdigest() != e["link"]:
                return i
            prev = e["link"]
        return None


def hashed_result_record(result: str) -> str:
    """'Hashed' mode: detects later change of a stored result, but proves nothing about who produced it."""
    return "sha256:" + hashlib.sha256(result.encode()).hexdigest()
