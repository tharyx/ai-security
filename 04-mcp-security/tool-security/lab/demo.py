"""Run every tool attack against the vulnerable and the hardened tools, then scan tool definitions.

From the repository root:
    python 04-mcp-security/tool-security/lab/demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import attacks
import fakes
from secure_tools import SecureToolServer
from tool_scanner import scan
from vulnerable_tools import VulnerableToolServer


def world(tmp: Path, kind: str, case: str):
    ws = fakes.make_workspace(tmp / f"{kind}-{case}")
    net, shell = fakes.FakeNetwork(), fakes.FakeShell()
    cls = VulnerableToolServer if kind == "vulnerable" else SecureToolServer
    return cls(ws.root, net, shell), ws, net, shell


def grade(out: str, ws, net, shell) -> str:
    """Grade by impact: what was read, reached or run - not by error messages."""
    if ws.outside_secret in out or ws.sibling_secret in out:
        return "SECRET READ"
    if any(s in out for s in (net.metadata_secret, net.admin_secret, net.passwd_secret)):
        return "INTERNAL DATA"
    if any(p != "git" for p in shell.programs()):
        return "COMMAND RAN"
    if any(a.startswith("--output") for argv in shell.executed for a in argv[: argv.index("--") if "--" in argv else None]):
        return "OPTION INJECTED"
    if any(r["ip"] == "93.184.216.66" for r in net.requests):
        return "OFF-ALLOWLIST"
    if len(net.requests) > 1:
        return "EGRESS"
    if len(out) > 100_000:
        return f"{len(out):,} chars"
    if out.endswith("[truncated]"):
        return "ok (truncated)"
    return "blocked" if out.startswith("[refused") else "ok"


def run_case(tmp: Path, kind: str, case: str, action) -> str:
    server, ws, net, shell = world(tmp, kind, case)
    try:
        out = action(server, ws, kind)
    except Exception as exc:  # the vulnerable server has no input handling at all
        return f"CRASHED ({type(exc).__name__})"
    return grade(out, ws, net, shell)


def cases():
    for name, path in attacks.PATH_TRAVERSAL.items():
        def act(s, ws, kind, path=path):
            p = str(ws.root.parent / "secrets.txt") if path == attacks.OUTSIDE_FILE else path
            return s.call("read_file", {"path": p})
        yield f"path:{name}", act
    for name, url in attacks.SSRF.items():
        yield f"ssrf:{name}", lambda s, ws, kind, url=url: s.call("fetch_url", {"url": url})
    for name, (vargs, sargs) in attacks.COMMAND_INJECTION.items():
        yield f"cmd:{name}", lambda s, ws, kind, v=vargs, a=sargs: s.call("run_command", v if kind == "vulnerable" else a)
    for name, (tool, args) in attacks.SCHEMA_ABUSE.items():
        yield f"schema:{name}", lambda s, ws, kind, t=tool, a=args: s.call(t, a)
    yield "result:huge_response", lambda s, ws, kind: s.call("fetch_url", {"url": "https://docs.acme.example/big"})
    yield "indirect:shell_via_page", lambda s, ws, kind: s.summarize_url("https://docs.acme.example/release-notes")
    yield "indirect:egress_via_page", lambda s, ws, kind: s.summarize_url("https://docs.acme.example/faq")
    yield "benign:read_readme", lambda s, ws, kind: s.call("read_file", {"path": "docs/readme.md"})
    yield "benign:fetch_docs", lambda s, ws, kind: s.call("fetch_url", {"url": "https://docs.acme.example/guide"})
    yield "benign:git_status", lambda s, ws, kind: s.call(
        "run_command", {"command": "git status"} if kind == "vulnerable" else {"subcommand": "status"})


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        print(f"{'case':30} {'vulnerable':20} secure")
        print("-" * 70)
        for name, action in cases():
            v = run_case(tmp, "vulnerable", name.replace(":", "_"), action)
            s = run_case(tmp, "secure", name.replace(":", "_"), action)
            print(f"{name:30} {v:20} {s}")

    print("\nTool-definition scan (poisoned + benign servers):")
    print(f"{'server':13} {'tool':14} {'severity':8} {'rule':22} evidence")
    print("-" * 100)
    findings = scan({**attacks.BENIGN_SERVERS, **attacks.POISONED_SERVERS}, allowed_domains=frozenset({"acme.example"}))
    for f in findings:
        print(f"{f.server:13} {f.tool:14} {f.severity:8} {f.rule:22} {f.evidence!r}")
    print(f"\nBenign servers alone: {len(scan(attacks.BENIGN_SERVERS))} findings.")
    print("\nTip: switch a layer off, e.g. SecureToolServer(..., block_private_ips=False), and re-run.")


if __name__ == "__main__":
    main()
