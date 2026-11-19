"""A mini pickle scanner, to learn what the real `picklescan` tool does. Offline, no loading.

    python mini_picklescan.py <file-or-folder> [...]

Idea: a pickle is a program for a small stack machine. Opcodes GLOBAL / STACK_GLOBAL import a
Python object by name, and REDUCE calls it. ``pickletools.genops`` DECODES the stream without
running it, so we can list every object the file would import and judge them.

Verdicts: SAFE (only allowlisted imports or none), SUSPICIOUS (an import we do not know),
DANGEROUS (an import on the known-bad list), or UNPARSEABLE (the stream broke; do not trust it).

A fuller version with more evasion tests lives in
``06-ai-devsecops/docker/lab/pickle_scan.py``. The real tool is the ``picklescan`` package
(see ../../notebooks/picklescan-real-tool.ipynb).
"""

from __future__ import annotations

import io
import pickletools
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ALLOW = {"collections.OrderedDict", "torch._utils._rebuild_tensor_v2", "torch.FloatStorage",
         "numpy.core.multiarray._reconstruct", "numpy.ndarray", "numpy.dtype"}
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "importlib", "pty"}
DANGEROUS_NAMES = {"builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__", "builtins.open"}

STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"}


@dataclass
class Report:
    source: str
    imports: list[str] = field(default_factory=list)
    parse_error: str = ""

    @property
    def verdict(self) -> str:
        if any(i in DANGEROUS_NAMES or i.split(".")[0] in DANGEROUS_MODULES for i in self.imports):
            return "DANGEROUS"
        if self.parse_error and not self.imports:
            return "UNPARSEABLE"
        if self.parse_error or any(i not in ALLOW for i in self.imports):
            return "SUSPICIOUS"
        return "SAFE"


def scan_pickle_bytes(data: bytes, source: str = "<bytes>") -> Report:
    rep = Report(source)
    stack: list[str] = []   # strings pushed so far (for STACK_GLOBAL)
    memo: dict[int, str] = {}
    try:
        for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
            if op.name in STRING_OPS:
                stack.append(str(arg))
            elif op.name == "MEMOIZE":
                if stack:
                    memo[len(memo)] = stack[-1]
            elif op.name in {"BINGET", "LONG_BINGET"}:
                stack.append(memo.get(arg, "?"))
            elif op.name == "POP" and stack:
                stack.pop()
            elif op.name == "GLOBAL":
                rep.imports.append(str(arg).replace(" ", "."))
            elif op.name == "STACK_GLOBAL" and len(stack) >= 2:
                rep.imports.append(f"{stack[-2]}.{stack[-1]}")
    except Exception as exc:  # a broken stream AFTER a payload still ran the payload on load
        rep.parse_error = type(exc).__name__
    return rep


def scan_file(path: str | Path) -> Report:
    path = Path(path)
    data = path.read_bytes()
    if zipfile.is_zipfile(io.BytesIO(data)):  # PyTorch-style archives hold a pickle inside
        rep = Report(str(path))
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if name.endswith(".pkl"):
                    inner = scan_pickle_bytes(z.read(name), f"{path}:{name}")
                    rep.imports += inner.imports
                    rep.parse_error = rep.parse_error or inner.parse_error
        return rep
    if path.suffix == ".safetensors":  # data-only format: a JSON header then raw numbers
        return Report(str(path))
    return scan_pickle_bytes(data, str(path))


def scan_folder(folder: str | Path) -> list[Report]:
    return [scan_file(p) for p in sorted(Path(folder).rglob("*")) if p.is_file()]


def main(argv: list[str]) -> int:
    reports = []
    for arg in argv:
        p = Path(arg)
        reports += scan_folder(p) if p.is_dir() else [scan_file(p)]
    bad = 0
    for r in reports:
        print(f"{r.verdict:<12}{r.source}  {', '.join(r.imports)}")
        bad += r.verdict != "SAFE"
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
