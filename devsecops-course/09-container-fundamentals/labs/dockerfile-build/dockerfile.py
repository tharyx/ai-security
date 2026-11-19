"""Dockerfile parser + layer model + build cache + multi-stage builds (a teaching simulator, no Docker needed).

Real Docker (BuildKit) differs in details; the model keeps the ideas that matter for security and speed:
- Only RUN, COPY and ADD create filesystem layers. ENV, EXPOSE, CMD, USER, WORKDIR, LABEL ... are metadata.
- A layer's cache key = parent layer id + the instruction text (+ the digest of copied files for COPY/ADD).
- Changing one layer invalidates every layer after it.
- Multi-stage: only the LAST stage ends up in the image; COPY --from=<stage> carries single artifacts across.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

LAYER_INSTRUCTIONS = {"RUN", "COPY", "ADD"}
KNOWN = {"FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR",
         "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL", "MAINTAINER"}

# crude size model in KB for RUN steps, enough to compare 'fat' and 'slim' builds
RUN_SIZE_HINTS = [("apt-get install", 80_000), ("apk add", 12_000), ("pip install", 40_000), ("npm install", 60_000),
                  ("npm ci", 60_000), ("go build", 15_000), ("make", 20_000), ("gcc", 150_000)]
BASE_SIZE_KB = {"scratch": 0, "alpine": 7_000, "debian": 120_000, "ubuntu": 78_000, "python": 1_000_000,
                "golang": 850_000, "node": 1_100_000, "gcr.io/distroless/static": 2_500, "distroless": 20_000}


@dataclass
class Instruction:
    cmd: str
    args: str
    line: int


@dataclass
class Layer:
    id: str
    created_by: str
    size_kb: int
    cached: bool
    stage: str


@dataclass
class Stage:
    name: str
    base: str
    instructions: list[Instruction] = field(default_factory=list)


def parse(text: str) -> list[Instruction]:
    """Handle comments, blank lines and trailing-backslash continuations."""
    out: list[Instruction] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.startswith("#"):
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        buf += line
        cmd, _, args = buf.partition(" ")
        cmd = cmd.upper()
        if cmd not in KNOWN:
            raise ValueError(f"line {start}: unknown instruction {cmd!r}")
        out.append(Instruction(cmd, args.strip(), start))
        buf = ""
    return out


def stages(instrs: list[Instruction]) -> list[Stage]:
    res: list[Stage] = []
    for i in instrs:
        if i.cmd == "FROM":
            m = re.match(r"(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", i.args)
            base, name = m.group(1), m.group(2) or str(len(res))
            res.append(Stage(name, base))
        elif res:
            res[-1].instructions.append(i)
        else:
            if i.cmd != "ARG":
                raise ValueError("instruction before FROM")
    if not res:
        raise ValueError("no FROM")
    return res


def _digest(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _size(instr: Instruction, context: dict[str, int]) -> int:
    if instr.cmd in ("COPY", "ADD"):
        parts = [p for p in instr.args.split() if not p.startswith("--")]
        srcs = parts[:-1]
        return sum(sz for f, sz in context.items() if any(f == s or f.startswith(s.rstrip("/") + "/") or s in (".", "./") for s in srcs))
    for hint, kb in RUN_SIZE_HINTS:
        if hint in instr.args:
            return kb
    return 100


def _content_key(instr: Instruction, context: dict[str, int]) -> str:
    if instr.cmd not in ("COPY", "ADD") or "--from=" in instr.args:
        return ""
    parts = [p for p in instr.args.split() if not p.startswith("--")]
    srcs = parts[:-1]
    sel = sorted((f, sz) for f, sz in context.items() if any(f == s or f.startswith(s.rstrip("/") + "/") or s in (".", "./") for s in srcs))
    return str(sel)


def build(text: str, context: dict[str, int] | None = None, cache: set[str] | None = None) -> dict:
    """Return the image: final-stage layers (and metadata) plus all stage layers and cache hits.

    `context` maps build-context file -> size in KB (and a changed size stands in for changed content).
    `cache` is a set of layer ids from earlier builds.
    """
    context = context or {}
    cache = set() if cache is None else cache
    sts = stages(parse(text))
    all_layers: dict[str, list[Layer]] = {}
    meta: dict[str, str] = {}
    artifacts: dict[str, dict[str, int]] = {}
    for st in sts:
        parent = _digest("base:" + st.base)
        layers = [Layer(parent, f"FROM {st.base}", BASE_SIZE_KB.get(st.base.split(":")[0], 50_000), True, st.name)]
        meta = {}
        for ins in st.instructions:
            if ins.cmd in LAYER_INSTRUCTIONS:
                key = _content_key(ins, context)
                lid = _digest(f"{parent}|{ins.cmd} {ins.args}|{key}")
                size = _size(ins, context)
                if "--from=" in ins.args:
                    src = re.search(r"--from=(\S+)", ins.args).group(1)
                    size = sum(artifacts.get(src, {}).values()) or 1_000
                layers.append(Layer(lid, f"{ins.cmd} {ins.args}", size, lid in cache, st.name))
                cache.add(lid)
                parent = lid
            else:
                if ins.cmd in ("USER", "CMD", "ENTRYPOINT", "WORKDIR"):
                    meta[ins.cmd] = ins.args
        all_layers[st.name] = layers
        artifacts[st.name] = {l.id: l.size_kb for l in layers[-1:]}
    final = sts[-1].name
    return {
        "layers": all_layers[final],
        "stages": all_layers,
        "meta": meta,
        "size_kb": sum(l.size_kb for l in all_layers[final]),
        "discarded_stages": [n for n in all_layers if n != final],
        "hits": sum(1 for s in all_layers.values() for l in s[1:] if l.cached),
        "misses": sum(1 for s in all_layers.values() for l in s[1:] if not l.cached),
    }


def explain_cache(before: dict, after: dict) -> list[str]:
    """Say which layers were rebuilt after a change and why."""
    out = []
    broke = False
    for b, a in zip(before["layers"], after["layers"]):
        if a.id != b.id:
            out.append(("REBUILT" if not broke else "REBUILT (parent changed)") + f": {a.created_by}")
            broke = True
        else:
            out.append(f"cached : {a.created_by}")
    return out
