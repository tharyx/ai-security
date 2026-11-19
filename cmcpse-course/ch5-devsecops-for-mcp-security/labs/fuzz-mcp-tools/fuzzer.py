"""A small mutation and grammar based fuzzer for MCP tool inputs. Standard library only.

It reads each tool's `inputSchema` from `tools/list`, builds valid arguments from seed values,
then mutates them: attack payload dictionaries (traversal, shell metacharacters, SSRF URLs),
random byte-level mutations, type confusion, missing and extra arguments.

Every call runs inside `sandbox()`. The sandbox replaces subprocess, os.system and urlopen with
recorders, so a "command injection" is detected by what the server TRIED to run, and nothing
real ever runs or connects.

Oracles (what counts as a finding):
  crash              an exception escaped the server's request handler
  path-traversal     a canary that lives OUTSIDE the notes directory came back to the client
  command-injection  the server built a shell string containing metacharacters from the input
  ssrf               the server tried to fetch a URL that is not on the allowed list
  info-leak          an error response contains a traceback, a source path or a temp path

Use Hypothesis or atheris for bigger campaigns (see README). This file shows the ideas with no
dependencies.
"""

from __future__ import annotations

import contextlib
import importlib.util
import os
import random
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

ALLOWED_FETCH_HOSTS = {"example.com", "docs.example.com"}
SHELL_META = set(";|&$`\n<>(){}")

SEEDS = {
    "name": "hello.txt", "host": "example.com", "url": "https://example.com/",
    "price": 10, "percent": 5, "total": 100, "people": 2,
}

PAYLOADS = {
    "traversal": ["../secret.txt", "..\\secret.txt", "....//secret.txt", "{SECRET}", "notes/../../secret.txt", "..%2fsecret.txt", "hello.txt\x00.png"],
    "shell": ["x; id", "x && id", "x | id", "$(id)", "`id`", "x\nid", "-c id", "a b c"],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin", "http://localhost/",
        "file:///etc/passwd", "https://example.com@evil.example/", "http://[::1]/", "gopher://evil.example/",
        "https://example.com.evil.example/", "ftp://example.com/",
    ],
    "format": ["%s%s%s%n", "{0.__class__}", "${jndi:ldap://x}", "{{7*7}}"],
    "weird": ["", " ", "‮", "\u0000", "A" * 10000, "\U0001f600" * 50, "null", "true", "../" * 200],
}
NUMBERS = [0, -1, 1, 2**31, 2**63, -(2**63), 0.1, 1e308, float("inf"), float("nan")]
CONFUSION = [None, True, [], {}, "", "5", [1, 2], {"a": 1}, 3.5]


@dataclass
class Effects:
    shell_calls: list = field(default_factory=list)
    urls: list = field(default_factory=list)


@dataclass
class Finding:
    kind: str
    tool: str
    detail: str
    arguments: object

    def __str__(self) -> str:
        shown = repr(self.arguments)
        return f"[{self.kind}] {self.tool}: {self.detail}   input={shown[:90]}"


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return b"fake response body"


@contextlib.contextmanager
def sandbox():
    """Replace everything dangerous with recorders. Yields an Effects object."""
    effects = Effects()

    def fake_run(cmd, *args, **kwargs):
        effects.shell_calls.append((cmd, bool(kwargs.get("shell"))))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def fake_system(cmd):
        effects.shell_calls.append((cmd, True))
        return 0

    def fake_urlopen(url, *args, **kwargs):
        effects.urls.append(url if isinstance(url, str) else getattr(url, "full_url", str(url)))
        return _FakeResponse()

    with mock.patch.object(subprocess, "run", fake_run), \
            mock.patch.object(subprocess, "Popen", fake_run), \
            mock.patch.object(subprocess, "check_output", fake_run), \
            mock.patch.object(os, "system", fake_system), \
            mock.patch.object(os, "popen", fake_system), \
            mock.patch.object(urllib.request, "urlopen", fake_urlopen):
        yield effects


def load_package(path: str | Path, name: str):
    """Load a package directory (with __init__.py and relative imports) under a unique name."""
    path = Path(path).resolve()
    unique = f"fuzz_{name}_{abs(hash(str(path))) % 10**8}"
    for key in [k for k in sys.modules if k == unique or k.startswith(unique + ".")]:
        del sys.modules[key]
    spec = importlib.util.spec_from_file_location(unique, path / "__init__.py", submodule_search_locations=[str(path)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[unique] = package
    spec.loader.exec_module(package)
    server = importlib.import_module(unique + ".server")
    config = importlib.import_module(unique + ".config")
    return server, config


class Workspace:
    """A temp dir with a notes folder and a canary file OUTSIDE it (what traversal should not reach)."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.notes = root / "notes"
        self.notes.mkdir()
        (self.notes / "hello.txt").write_text("hello from notes", encoding="utf-8")
        self.secret = root / "secret.txt"
        self.canary = "CANARY-outside-notes-7f3a9c"
        self.secret.write_text(self.canary, encoding="utf-8")
        self.root = str(root)

    def close(self):
        self.tmp.cleanup()


def _mutate_string(rng: random.Random, base: str, ws: Workspace) -> str:
    kind = rng.choice(["payload", "insert", "replace", "dup", "trunc", "case"])
    if kind == "payload":
        group = rng.choice(list(PAYLOADS))
        return rng.choice(PAYLOADS[group]).replace("{SECRET}", str(ws.secret))
    if kind == "insert":
        pos = rng.randrange(len(base) + 1)
        return base[:pos] + rng.choice(["; ", "../", "\x00", "$(", "`", "|", "\n", "%00", "\\"]) + base[pos:]
    if kind == "replace" and base:
        pos = rng.randrange(len(base))
        return base[:pos] + chr(rng.randrange(1, 0x2FF)) + base[pos + 1:]
    if kind == "dup":
        return base * rng.randrange(2, 400)
    if kind == "trunc":
        return base[: rng.randrange(len(base) + 1)]
    return base.swapcase()


def _mutate_value(rng: random.Random, kind: str, base, ws: Workspace):
    roll = rng.random()
    if roll < 0.15:
        return rng.choice(CONFUSION)
    if kind == "string":
        return _mutate_string(rng, str(base), ws)
    return rng.choice(NUMBERS)


def generate_arguments(rng: random.Random, schema: dict, ws: Workspace) -> object:
    props = schema.get("properties", {})
    args = {name: SEEDS.get(name, "x" if spec["type"] == "string" else 1) for name, spec in props.items()}
    roll = rng.random()
    if roll < 0.05:
        return rng.choice([None, [], "x", 7, {"unexpected": 1}])
    if roll < 0.12 and args:
        del args[rng.choice(list(args))]
        return args
    if roll < 0.18:
        args["extra"] = rng.choice(["x", 1, None])
    for name in rng.sample(list(props), k=rng.randrange(1, len(props) + 1)) if props else []:
        args[name] = _mutate_value(rng, props[name]["type"], args[name], ws)
    return args


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _check(tool: str, arguments, response, effects: Effects, ws: Workspace) -> list[Finding]:
    found = []
    text = repr(response)
    if ws.canary in text:
        found.append(Finding("path-traversal", tool, "canary from outside the notes directory was returned", arguments))
    if "error" in response:
        leaked = [m for m in ("Traceback", 'File "', ".py", ws.root) if m in text]
        if leaked:
            found.append(Finding("info-leak", tool, f"error response contains {leaked[0]!r}", arguments))
    inputs = [s for s in _strings(arguments) if SHELL_META & set(s)]
    for cmd, shell_form in effects.shell_calls:
        if isinstance(cmd, str) and any(s in cmd for s in inputs):
            found.append(Finding("command-injection", tool, f"shell string built from input: {cmd[:60]!r}", arguments))
    for url in effects.urls:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or (parts.hostname or "") not in ALLOWED_FETCH_HOSTS:
            found.append(Finding("ssrf", tool, f"server fetched {url[:60]!r}", arguments))
    return found


def fuzz(server_dir: str | Path, iterations: int = 400, seed: int = 1234) -> list[Finding]:
    """Fuzz one server package. Returns the first finding per (kind, tool)."""
    rng = random.Random(seed)
    ws = Workspace()
    try:
        server, config = load_package(server_dir, Path(server_dir).name)
        config.NOTES_DIR = str(ws.notes)
        tools = server.handle({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})["result"]["tools"]
        unique: dict[tuple[str, str], Finding] = {}
        # Phase 1: every payload against every string parameter (grammar part, deterministic).
        cases = []
        for tool in tools:
            for pname, spec in tool["inputSchema"].get("properties", {}).items():
                if spec["type"] == "string":
                    for group in PAYLOADS.values():
                        for payload in group:
                            args = {n: SEEDS.get(n, "x") for n in tool["inputSchema"]["properties"]}
                            args[pname] = payload.replace("{SECRET}", str(ws.secret))
                            cases.append((tool["name"], args))
        # Phase 2: random mutation of seeds (mutation part, seeded).
        for _ in range(iterations):
            tool = rng.choice(tools)
            cases.append((tool["name"], generate_arguments(rng, tool["inputSchema"], ws)))
        for name, arguments in cases:
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
            with sandbox() as effects:
                try:
                    response = server.handle(request)
                except Exception as exc:  # noqa: BLE001 - this is exactly what we hunt for
                    finding = Finding("crash", name, f"{type(exc).__name__} escaped the handler", arguments)
                    unique.setdefault((finding.kind, finding.tool), finding)
                    continue
            for finding in _check(name, arguments, response, effects, ws):
                unique.setdefault((finding.kind, finding.tool), finding)
        return sorted(unique.values(), key=lambda f: (f.kind, f.tool))
    finally:
        ws.close()


def summarize(findings: list[Finding]) -> dict:
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.kind] = out.get(finding.kind, 0) + 1
    return dict(sorted(out.items()))
