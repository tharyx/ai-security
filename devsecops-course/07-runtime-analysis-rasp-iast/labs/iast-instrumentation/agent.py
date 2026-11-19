"""A pure-Python "IAST agent" (report mode) that can also run in "protect" mode (RASP).

It monkey-patches the sink methods of the app (``Database.execute``, ``Shell.run``, ``Files.open_file``).
At each sink call it looks at the arguments:

  * is any part of the *code-like* argument tainted (from the request)?       -> IAST: a vulnerable FLOW
  * does the tainted part change the structure (quote, ``;``, ``..``, ``|``)?  -> RASP: an attack in progress

IAST reports the flow even for harmless test input ("alice"), because the code is built unsafely.
RASP (mode="block") only blocks when the payload is actually hostile, so normal users are not hurt.
"""

from __future__ import annotations

import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import load_lab_module

taint = load_lab_module(str(Path(__file__).resolve()), "taint")
tinyapp = load_lab_module(str(Path(__file__).resolve()), "tinyapp")

PAYLOAD_PATTERNS = {
    "SQL_INJECTION": re.compile(r"['\";]|--|\bunion\b|\bor\b\s+\S+\s*=", re.I),
    "COMMAND_INJECTION": re.compile(r"[;&|`\n]|\$\("),
    "PATH_TRAVERSAL": re.compile(r"\.\.|^/"),
}


class AttackBlocked(Exception):
    def __init__(self, kind, endpoint):
        super().__init__(f"{kind} blocked at runtime (endpoint {endpoint})")
        self.kind, self.endpoint = kind, endpoint


@dataclass
class Vulnerability:
    kind: str
    endpoint: str
    sink: str
    source: str
    trace: list
    sink_value: str
    malicious_payload: bool
    blocked: bool = False


@dataclass
class IastAgent:
    mode: str = "report"                      # "report" (IAST) or "block" (RASP protect mode)
    block_kinds: set = field(default_factory=lambda: {"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"})
    findings: list = field(default_factory=list)
    sink_calls: int = 0
    sink_time: float = 0.0
    _current: str = "unknown"
    _orig: dict = field(default_factory=dict)

    # ---------------------------------------------------------------- install / uninstall
    def install(self):
        T = tinyapp
        self._wrap(T.Database, "execute", "SQL_INJECTION", "Database.execute", arg=0)
        self._wrap(T.Shell, "run", "COMMAND_INJECTION", "Shell.run", arg=0)
        self._wrap(T.Files, "open_file", "PATH_TRAVERSAL", "Files.open_file", arg=0)
        return self

    def uninstall(self):
        for (cls, name), fn in self._orig.items():
            setattr(cls, name, fn)
        self._orig.clear()

    def __enter__(self):
        return self.install()

    def __exit__(self, *exc):
        self.uninstall()

    @contextmanager
    def request(self, endpoint: str):
        prev, self._current = self._current, endpoint
        try:
            yield
        finally:
            self._current = prev

    def _wrap(self, cls, name, kind, sink_name, arg):
        original = getattr(cls, name)
        self._orig[(cls, name)] = original
        agent = self

        def wrapper(obj, *args, **kw):
            t0 = time.perf_counter()
            agent.sink_calls += 1
            value = args[arg] if len(args) > arg else None
            if taint.is_tainted(value):
                agent._on_tainted_sink(kind, sink_name, value)  # may raise AttackBlocked
            agent.sink_time += time.perf_counter() - t0
            return original(obj, *args, **kw)

        wrapper.__wrapped__ = original
        setattr(cls, name, wrapper)

    # ---------------------------------------------------------------- analysis
    def _on_tainted_sink(self, kind, sink_name, value):
        tainted_bits = value.tainted_text()
        hostile = any(PAYLOAD_PATTERNS[kind].search(text) for text, _ in tainted_bits)
        caller = taint.where(3)  # 0 where, 1 this method, 2 wrapper, 3 the app code that called the sink
        source = tainted_bits[0][1]
        trace = [f"SOURCE   {source}"] + [f"PROPAGATE {s}" for s in value.trail] + [f"SINK     {sink_name} called at {caller}"]
        blocked = self.mode == "block" and hostile and kind in self.block_kinds
        self.findings.append(Vulnerability(kind, self._current, sink_name, source, trace, str(value), hostile, blocked))
        if blocked:
            raise AttackBlocked(kind, self._current)

    # ---------------------------------------------------------------- reporting
    def report(self) -> list:
        """Unique vulnerable flows (same kind + endpoint + sink location collapsed)."""
        seen, out = set(), []
        for f in self.findings:
            key = (f.kind, f.endpoint, f.trace[-1])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
