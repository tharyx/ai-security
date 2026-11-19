"""A logging "man in the middle" for MCP stdio traffic, for DEFENDERS and learners.

Put it between a client and a server. It forwards every line unchanged and writes one log
line per JSON-RPC message with a timestamp and a direction. Secrets are redacted in the LOG,
never in the traffic (the proxy does not alter messages).

    client  <--stdin/stdout-->  proxy.py  <--stdin/stdout-->  real server

Usage:
    python proxy.py --log traffic.log -- python server.py --config config.json

Only use it on your own lab traffic. The log still holds tool arguments and results, so treat
the log file as sensitive (redaction is best effort, not a guarantee).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any, TextIO

REDACTED = "[REDACTED]"
SENSITIVE_KEY = re.compile(r"(token|secret|password|passwd|authorization|api[_-]?key|credential|cookie)", re.I)
SECRET_VALUE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/=-]{8,}"          # Authorization header values
    r"|sk-[A-Za-z0-9_-]{16,}"                       # common API key shape
    r"|gh[pousr]_[A-Za-z0-9]{20,}"                  # GitHub token shape
    r"|AKIA[0-9A-Z]{16}"                            # AWS access key id shape
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"  # JWT shape
)
SUSPICIOUS_DESCRIPTION = re.compile(r"(<important>|ignore (all |any )?previous|do not (tell|mention)|~/\.ssh|id_rsa)", re.I)


def redact(value: Any) -> Any:
    """Return a copy of a parsed JSON value with secrets masked."""
    if isinstance(value, dict):
        return {k: (REDACTED if SENSITIVE_KEY.search(str(k)) and not isinstance(v, (dict, list)) else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return SECRET_VALUE.sub(REDACTED, value)
    return value


def classify(msg: Any) -> str:
    if not isinstance(msg, dict):
        return "invalid"
    if "method" in msg:
        return "request" if "id" in msg else "notification"
    if "error" in msg:
        return "error"
    return "response" if "result" in msg else "invalid"


def alerts_for(msg: Any) -> list[str]:
    """Cheap defender hints. Not a scanner: see 04-mcp-security/tool-security for real checks."""
    found: list[str] = []
    if isinstance(msg, dict) and isinstance(msg.get("result"), dict):
        for tool in msg["result"].get("tools", []) or []:
            if isinstance(tool, dict) and SUSPICIOUS_DESCRIPTION.search(str(tool.get("description", ""))):
                found.append(f"tool '{tool.get('name')}' has a suspicious description")
    return found


def format_line(direction: str, raw: str, now: datetime | None = None) -> str:
    """One log line for one raw protocol line. direction is 'C->S' or 'S->C'."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%H:%M:%S.%f")[:-3]
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return f"{stamp}  {direction}  NOT-JSON   {SECRET_VALUE.sub(REDACTED, raw.strip())[:200]}"
    kind = classify(msg)
    label = msg.get("method", "") if isinstance(msg, dict) else ""
    rid = msg.get("id", "-") if isinstance(msg, dict) else "-"
    body = json.dumps(redact(msg), separators=(",", ":"))
    line = f"{stamp}  {direction}  {kind:<12} id={rid!s:<3} {label:<26} {body}"
    for a in alerts_for(msg):
        line += f"\n{stamp}  !!    ALERT {a}"
    return line


class Proxy:
    def __init__(self, server_cmd: list[str], log: TextIO) -> None:
        self.log, self._lock = log, threading.Lock()
        self.server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=None, text=True, encoding="utf-8")

    def _log(self, direction: str, raw: str) -> None:
        with self._lock:
            self.log.write(format_line(direction, raw) + "\n")
            self.log.flush()

    def _server_to_client(self, out: TextIO) -> None:
        assert self.server.stdout is not None
        for line in self.server.stdout:
            self._log("S->C", line)
            out.write(line)
            out.flush()

    def run(self, stdin: TextIO, stdout: TextIO) -> int:
        pump = threading.Thread(target=self._server_to_client, args=(stdout,), daemon=True)
        pump.start()
        assert self.server.stdin is not None
        for line in stdin:
            if not line.strip():
                continue
            self._log("C->S", line)
            self.server.stdin.write(line if line.endswith("\n") else line + "\n")
            self.server.stdin.flush()
        self.server.stdin.close()  # client hung up: tell the server (stdio shutdown)
        pump.join(timeout=5)
        return self.server.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", help="log file (default: stderr)")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER, help="-- <command that starts the server>")
    args = parser.parse_args()
    cmd = [a for a in args.server_cmd if a != "--"] if args.server_cmd[:1] == ["--"] else args.server_cmd
    if not cmd:
        parser.error("give the server command after --")
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    log = open(args.log, "a", encoding="utf-8") if args.log else sys.stderr
    try:
        return Proxy(cmd, log).run(sys.stdin, sys.stdout)
    finally:
        if args.log:
            log.close()


if __name__ == "__main__":
    raise SystemExit(main())
