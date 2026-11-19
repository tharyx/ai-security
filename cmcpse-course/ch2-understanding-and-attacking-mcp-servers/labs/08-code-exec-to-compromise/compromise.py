"""From code execution to complete compromise, entirely inside a simulation.

Nothing here runs a real command or touches the real file system:
  * ``VFS``       an in-memory file system with owners, permissions and symlinks;
  * ``FakeShell`` a toy shell that understands only echo, cat, ls, whoami, ping (pretend), printenv;
  * ``CloudAPI``  a fake cloud control plane that accepts a canary key.

Vulnerable MCP server ``vuln-ops``  (runs as the powerful user ``svc``)
    run_command(command)   passes the whole string to the shell        -> command injection / code execution
    ping_host(host)        builds "ping <host>" and runs it in the shell -> argument/command injection
    read_file(path)        'inside the workspace' check = string prefix + normpath, symlinks not resolved
                           -> sibling-prefix bypass and symlink escape (the pattern reported for the
                              Filesystem MCP server CVE-2025-53109/53110; verify details at source)
Hardened MCP server ``safe-ops``     (runs as the unprivileged user ``mcp``)
    ping_host(host)        strict hostname pattern, argv list, no shell
    read_file(path)        resolve symlinks first, then component-wise containment, plus OS permissions
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Any

from aisec_lab import load_lab_module, make_canary

rpc = load_lab_module(__file__, "rpc")

ROOT = "/srv/app/workspace"
CREDS = "/home/svc/.cloud/credentials"
CLOUD_KEY = make_canary("CANARY-CLOUDKEY")


# ---------------------------------------------------------------------------------
# Simulated machine
# ---------------------------------------------------------------------------------
@dataclass
class Entry:
    owner: str
    text: str
    world_readable: bool = False


class VFS:
    def __init__(self) -> None:
        self.files = {
            f"{ROOT}/readme.txt": Entry("svc", "Project readme.", True),
            "/srv/app/workspace-secrets/notes.txt": Entry("svc", "internal notes (a sibling folder that shares the prefix)"),
            CREDS: Entry("svc", f"cloud_api_key={CLOUD_KEY}\nendpoint=https://cloud.corp.example"),
            "/etc/hostname": Entry("root", "build-host-01", True),
        }
        self.links = {f"{ROOT}/shortcut": CREDS}  # a symlink inside the workspace pointing outside it

    @staticmethod
    def norm(path: str) -> str:
        return posixpath.normpath(path)

    def resolve(self, path: str) -> str:
        p = self.norm(path)
        for _ in range(8):
            if p not in self.links:
                return p
            p = self.norm(self.links[p])
        raise OSError("too many symlinks")

    def read(self, path: str, user: str, *, follow: bool = True) -> str:
        p = self.resolve(path) if follow else self.norm(path)
        entry = self.files.get(p)
        if entry is None:
            raise FileNotFoundError(p)
        if entry.owner != user and not entry.world_readable:
            raise PermissionError(p)
        return entry.text


class FakeShell:
    def __init__(self, vfs: VFS, user: str) -> None:
        self.vfs, self.user = vfs, user
        self.history: list[str] = []

    def run(self, cmdline: str) -> str:
        """Like ``sh -c``: ';', '&&' and newlines chain commands. That is exactly the injection surface."""
        return "\n".join(self.run_argv(shlex.split(p)) for p in re.split(r";|&&|\n", cmdline) if p.strip())

    def run_argv(self, argv: list[str]) -> str:
        self.history.append(" ".join(argv))
        cmd, args = argv[0], argv[1:]
        try:
            if cmd == "echo":
                return " ".join(args)
            if cmd == "cat":
                return self.vfs.read(args[0], self.user)
            if cmd == "whoami":
                return self.user
            if cmd == "ls":
                return "\n".join(sorted(p for p in self.vfs.files if p.startswith(args[0].rstrip("/") + "/"))) if args else ""
            if cmd == "ping":
                return f"PING {args[-1]}: 1 packet transmitted, 1 received (pretend)"
        except (FileNotFoundError, PermissionError) as exc:
            return f"{cmd}: {type(exc).__name__}: {exc}"
        return f"sh: {cmd}: not found"


class CloudAPI:
    """A fake cloud control plane. Keys carry scopes; ``create_admin`` is the 'game over' action."""

    def __init__(self) -> None:
        self.keys: dict[str, set[str]] = {CLOUD_KEY: {"list_buckets", "create_admin"}}
        self.admins: list[str] = []

    def issue_key(self, scopes: set[str]) -> str:
        key = make_canary("CANARY-SCOPED")
        self.keys[key] = set(scopes)
        return key

    def request(self, action: str, key: str, **kw: Any) -> Any:
        if action not in self.keys.get(key, set()):
            raise PermissionError(f"{action}: key not accepted or scope missing")
        if action == "list_buckets":
            return ["prod-data", "backups"]
        self.admins.append(kw["name"])
        return f"admin {kw['name']} created"

    @property
    def compromised(self) -> bool:
        return bool(self.admins)


# ---------------------------------------------------------------------------------
# The two MCP servers
# ---------------------------------------------------------------------------------
def vulnerable_server(vfs: VFS | None = None) -> "rpc.Server":
    vfs = vfs or VFS()
    shell = FakeShell(vfs, "svc")

    def read_file(path: str) -> str:
        p = vfs.norm(path)
        if not p.startswith(ROOT):          # BUG 1: string prefix, so /srv/app/workspace-secrets passes
            raise rpc.ToolError("outside workspace")
        return vfs.read(p, "svc", follow=True)  # BUG 2: the OS follows a symlink that points outside

    srv = rpc.Server("vuln-ops", "0.1.0", [
        rpc.Tool("run_command", "Run a shell command on the server.", rpc.schema(command={"type": "string"}), lambda command: shell.run(command)),
        rpc.Tool("ping_host", "Ping a host.", rpc.schema(host={"type": "string"}), lambda host: shell.run(f"ping {host}")),
        rpc.Tool("read_file", "Read a file in the workspace.", rpc.schema(path={"type": "string"}), read_file),
    ])
    srv.vfs, srv.shell = vfs, shell  # type: ignore[attr-defined]
    return srv


HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def hardened_server(vfs: VFS | None = None, *, contain_paths: bool = True) -> "rpc.Server":
    """``contain_paths=False`` simulates a forgotten containment check, to show OS permissions still hold."""
    vfs = vfs or VFS()
    shell = FakeShell(vfs, "mcp")

    def ping_host(host: str) -> str:
        if not HOST_RE.fullmatch(host):
            raise rpc.ToolError("invalid host")
        return shell.run_argv(["ping", host])  # argv list: there is no shell to inject into

    def read_file(path: str) -> str:
        if contain_paths:
            real = vfs.resolve(path)  # resolve symlinks BEFORE checking
            if not (real == ROOT or real.startswith(ROOT + "/")):  # component-wise, not a bare prefix
                raise rpc.ToolError("outside workspace")
        try:
            return vfs.read(path, "mcp")  # runs as an unprivileged user
        except (FileNotFoundError, PermissionError):
            raise rpc.ToolError("cannot read") from None

    srv = rpc.Server("safe-ops", "0.2.0", [
        rpc.Tool("ping_host", "Ping a hostname.", rpc.schema(host={"type": "string", "pattern": HOST_RE.pattern, "maxLength": 253}), ping_host),
        rpc.Tool("read_file", "Read a file in the workspace.", rpc.schema(path={"type": "string", "maxLength": 200}), read_file),
    ])
    srv.vfs, srv.shell = vfs, shell  # type: ignore[attr-defined]
    return srv


# ---------------------------------------------------------------------------------
# The attack, step by step (harmless payloads only: echo and read a canary)
# ---------------------------------------------------------------------------------
def attack(server: "rpc.Server", cloud: CloudAPI) -> dict[str, Any]:
    steps: list[str] = []
    tools = [t["name"] for t in rpc.request(server.handle, "tools/list")["result"]["tools"]]
    steps.append(f"1 recon: tools = {tools}")

    def try_call(tool: str, **args: Any) -> str | None:
        try:
            return rpc.call_tool(server.handle, tool, args)
        except RuntimeError:
            return None

    out = try_call("run_command", command="echo pwned-marker") if "run_command" in tools else None
    steps.append(f"2 code execution via run_command: {'YES' if out and 'pwned-marker' in out else 'no'}")
    out = try_call("ping_host", host="127.0.0.1; echo pwned-marker")
    steps.append(f"3 injection via ping_host: {'YES' if out and 'pwned-marker' in out else 'no'}")

    loot = None
    for label, path in (("sibling prefix", "/srv/app/workspace-secrets/notes.txt"), ("symlink", f"{ROOT}/shortcut"),
                        ("traversal", f"{ROOT}/../../../home/svc/.cloud/credentials")):
        got = try_call("read_file", path=path)
        steps.append(f"4 file read via {label}: {'READ' if got else 'denied'}")
        loot = loot or (got if got and "cloud_api_key" in got else None)
    if loot is None and "run_command" in tools:
        loot = try_call("run_command", command=f"cat {CREDS}")
        steps.append(f"5 credentials via shell: {'READ' if loot else 'denied'}")
    key = re.search(r"cloud_api_key=(\S+)", loot or "")
    if key:
        try:
            cloud.request("list_buckets", key.group(1))
            cloud.request("create_admin", key.group(1), name="attacker-admin")
            steps.append("6 pivot: used the stolen key against the cloud API, created an admin user")
        except PermissionError as exc:
            steps.append(f"6 pivot failed: {exc}")
    else:
        steps.append("6 pivot: no credentials obtained")
    return {"steps": steps, "key_stolen": bool(key), "compromised": cloud.compromised}
