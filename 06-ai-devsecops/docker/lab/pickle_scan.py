"""Scan model files for code-execution risk WITHOUT loading them.

    python pickle_scan.py model.pkl model.pt model.safetensors

Why this exists
---------------
A pickle file is not data. It is a small program for a stack machine. Two opcodes make
it dangerous:

* GLOBAL / STACK_GLOBAL  - import any Python object by name, e.g. ``os.system``
* REDUCE (and INST/OBJ/NEWOBJ) - call that object with arguments

``pickle.load()`` runs that program. So does ``torch.load()`` with ``weights_only=False``,
``joblib.load()`` and ``numpy.load(allow_pickle=True)``. A model file from the internet
is therefore untrusted code.

This scanner walks the opcodes with ``pickletools.genops``. That function only DECODES
the stream; it never imports or calls anything. We collect every global the pickle
would import and compare it with an allowlist.

Verdicts
    SAFE       only allowlisted globals (or none)
    UNSAFE     a global that is not on the allowlist, or a stream we could not fully parse
    DANGEROUS  a global on the known-dangerous list (os.system, builtins.exec, ...)

Defense layers in ``safe_load_model`` (each can be switched off to see what it buys):
    prefer_safetensors  data-only format; nothing to execute
    scan                static scan; refuse anything that is not SAFE
    restricted          a RestrictedUnpickler that refuses non-allowlisted globals at load
                        time, even if the scanner was fooled
"""

from __future__ import annotations

import io
import json
import pickle
import pickletools
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Globals that ordinary model / tensor pickles need. Everything else is refused.
SAFE_GLOBALS = {
    "collections.OrderedDict",
    "_codecs.encode",                       # how protocol 0-2 pickles store bytes
    "builtins.set", "builtins.frozenset", "builtins.bytearray", "builtins.complex", "builtins.slice",
    "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_parameter",
    "torch.FloatStorage", "torch.HalfStorage", "torch.BFloat16Storage", "torch.LongStorage",
    "torch.IntStorage", "torch.ByteStorage", "torch.BoolStorage",
    "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.ndarray", "numpy.dtype",
}

# Known-bad modules and callables seen in malicious model files. A denylist is NOT the
# control (attackers find new gadgets); it only makes the verdict more specific.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "runpy", "importlib", "socket", "shutil", "pty",
    "webbrowser", "pickle", "_pickle", "marshal", "ctypes", "code", "commands", "requests",
    "urllib", "http", "httplib", "asyncio", "multiprocessing", "pip", "torch.hub",
}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr",
                      "delattr", "globals", "locals", "breakpoint", "input", "vars"}

STRING_OPS = {"UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
              "STRING", "BINSTRING", "SHORT_BINSTRING"}
MEMO_PUT = {"PUT", "BINPUT", "LONG_BINPUT"}
MEMO_GET = {"GET", "BINGET", "LONG_BINGET"}
CALL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"}
NO_STACK_EFFECT = MEMO_PUT | {"MEMOIZE", "FRAME", "PROTO", "STOP"}


@dataclass
class ScanResult:
    source: str
    format: str                                   # pickle | zip(pickle) | safetensors
    globals: list[str] = field(default_factory=list)
    calls: int = 0                                # REDUCE/INST/OBJ/NEWOBJ count
    errors: list[str] = field(default_factory=list)

    @property
    def dangerous(self) -> list[str]:
        return [g for g in self.globals if is_dangerous(g)]

    @property
    def unknown(self) -> list[str]:
        return [g for g in self.globals if g not in SAFE_GLOBALS and not is_dangerous(g)]

    @property
    def verdict(self) -> str:
        if self.dangerous:
            return "DANGEROUS"
        if self.unknown or self.errors:
            return "UNSAFE"  # fail closed: unknown imports or a stream we could not read
        return "SAFE"


def is_dangerous(qualified: str) -> bool:
    module, _, name = qualified.rpartition(".")
    if module in {"builtins", "__builtin__"}:
        return name in DANGEROUS_BUILTINS
    return any(module == m or module.startswith(m + ".") for m in DANGEROUS_MODULES)


# --------------------------------------------------------------------------- pickle

def _scan_one(stream: io.BytesIO, result: ScanResult) -> None:
    """Decode ONE pickle (up to STOP) from ``stream``. Never imports or calls anything."""
    memo: dict[int, object] = {}
    last: object = None              # value of the most recent push, if it was a string
    pushes: list[object] = []        # recent pushed values (str or None), for STACK_GLOBAL
    for opcode, arg, _pos in pickletools.genops(stream):
        name = opcode.name
        if name in STRING_OPS:
            last = arg.decode("latin-1") if isinstance(arg, bytes) else str(arg)
            pushes.append(last)
        elif name == "MEMOIZE":
            memo[len(memo)] = last
        elif name in MEMO_PUT:
            memo[arg] = last
        elif name in MEMO_GET:
            last = memo.get(arg)
            pushes.append(last)
        elif name in {"GLOBAL", "INST"}:
            module, _, attr = str(arg).partition(" ")
            result.globals.append(f"{module}.{attr}")
            last = None
            pushes.append(None)
        elif name == "STACK_GLOBAL":
            module, attr = (pushes[-2], pushes[-1]) if len(pushes) >= 2 else (None, None)
            if isinstance(module, str) and isinstance(attr, str):
                result.globals.append(f"{module}.{attr}")
            else:
                result.globals.append("<unresolved>.<STACK_GLOBAL>")  # fail closed
            last = None
            pushes.append(None)
        elif name not in NO_STACK_EFFECT:
            last = None
            if opcode.stack_after:
                pushes.append(None)
        if name in CALL_OPS:
            result.calls += 1


def scan_pickle_bytes(data: bytes, source: str = "<bytes>", fmt: str = "pickle",
                      result: ScanResult | None = None) -> ScanResult:
    result = result or ScanResult(source, fmt)
    stream = io.BytesIO(data)
    while stream.tell() < len(data):  # a file may hold several pickles back to back
        start = stream.tell()
        try:
            _scan_one(stream, result)
        except Exception as exc:  # truncated or malformed: report, keep what we found
            result.errors.append(f"{source}: could not parse at byte {start}+: {exc}")
            break
        if stream.tell() == start:
            break
    return result


def scan_file(path: str | Path) -> ScanResult:
    path = Path(path)
    data = path.read_bytes()
    if path.suffix == ".safetensors":
        result = ScanResult(str(path), "safetensors")
        try:
            inspect_safetensors(data)
        except ValueError as exc:
            result.errors.append(str(exc))
        return result
    if zipfile.is_zipfile(io.BytesIO(data)):  # torch.save() format: a zip with data.pkl inside
        result = ScanResult(str(path), "zip(pickle)")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = [m for m in zf.namelist() if m.endswith(".pkl")]
            if not members:
                result.errors.append("zip archive without a .pkl member: unknown format")
            for member in members:
                scan_pickle_bytes(zf.read(member), f"{path.name}:{member}", result=result)
        return result
    return scan_pickle_bytes(data, str(path))


# --------------------------------------------------------------------------- safetensors

DTYPE_SIZES = {"BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1, "I16": 2, "U16": 2,
               "F16": 2, "BF16": 2, "I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8}
MAX_HEADER = 100 * 1024 * 1024


def inspect_safetensors(data: bytes) -> dict:
    """Validate a .safetensors file and return its header. Pure parsing: JSON + byte offsets.

    Layout: 8-byte little-endian header length N | N bytes of JSON | raw tensor bytes.
    There is no opcode, no import, nothing to execute. That is the whole point.
    """
    if len(data) < 8:
        raise ValueError("too short to be safetensors")
    (n,) = struct.unpack("<Q", data[:8])
    if n > MAX_HEADER or 8 + n > len(data):
        raise ValueError("header length is larger than the file")
    try:
        header = json.loads(data[8:8 + n].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"header is not valid JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise ValueError("header must be a JSON object")
    buffer_len, expected = len(data) - 8 - n, 0
    for tensor, info in sorted(((k, v) for k, v in header.items() if k != "__metadata__"),
                               key=lambda kv: kv[1].get("data_offsets", [0])[0]):
        dtype, shape, (begin, end) = info["dtype"], info["shape"], info["data_offsets"]
        if dtype not in DTYPE_SIZES:
            raise ValueError(f"{tensor}: unknown dtype {dtype}")
        count = 1
        for dim in shape:
            count *= dim
        if begin != expected or end - begin != count * DTYPE_SIZES[dtype] or end > buffer_len:
            raise ValueError(f"{tensor}: data_offsets do not match shape/dtype or file size")
        expected = end
    if expected != buffer_len:
        raise ValueError("unused bytes after the last tensor")
    return header


def write_safetensors(path: str | Path, tensors: dict[str, list[float]], metadata: dict | None = None) -> None:
    """Tiny writer for 1-D float32 tensors, so the lab needs no extra packages."""
    header: dict = {"__metadata__": metadata} if metadata else {}
    blob, offset = b"", 0
    for name, values in tensors.items():
        raw = struct.pack(f"<{len(values)}f", *values)
        header[name] = {"dtype": "F32", "shape": [len(values)], "data_offsets": [offset, offset + len(raw)]}
        blob, offset = blob + raw, offset + len(raw)
    head = json.dumps(header, separators=(",", ":")).encode()
    head += b" " * (-len(head) % 8)  # the format pads the header to 8 bytes
    Path(path).write_bytes(struct.pack("<Q", len(head)) + head + blob)


# --------------------------------------------------------------------------- secure loader

class UnsafeModelError(Exception):
    pass


class RestrictedUnpickler(pickle.Unpickler):
    """Load-time enforcement: only allowlisted globals may be imported."""

    def find_class(self, module: str, name: str):  # noqa: D401
        if f"{module}.{name}" not in SAFE_GLOBALS:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is not allowed")
        return super().find_class(module, name)


def safe_load_model(path: str | Path, *, prefer_safetensors: bool = True, scan: bool = True,
                    restricted: bool = True) -> object:
    """Load a model file with layered defenses. Returns the safetensors header or the object."""
    path = Path(path)
    if path.suffix == ".safetensors":
        return inspect_safetensors(path.read_bytes())
    if prefer_safetensors and path.suffix in {".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".ckpt"}:
        raise UnsafeModelError(f"{path.name}: pickle-based format; convert to safetensors first")
    if scan:
        result = scan_file(path)
        if result.verdict != "SAFE":
            raise UnsafeModelError(f"{path.name}: {result.verdict} {result.dangerous or result.unknown or result.errors}")
    with path.open("rb") as fh:
        if restricted:
            return RestrictedUnpickler(fh).load()
        return pickle.load(fh)  # only reached when every layer above is switched off or passed


def main(argv: list[str] | None = None) -> int:
    paths = argv if argv is not None else sys.argv[1:]
    worst = 0
    for p in paths:
        r = scan_file(p)
        print(f"{r.verdict:9} {r.format:12} calls={r.calls:<3} {p}")
        for g in r.dangerous:
            print(f"          dangerous import: {g}")
        for g in r.unknown:
            print(f"          not on allowlist: {g}")
        for e in r.errors:
            print(f"          error: {e}")
        worst = max(worst, {"SAFE": 0, "UNSAFE": 1, "DANGEROUS": 2}[r.verdict])
    return worst


if __name__ == "__main__":
    sys.exit(main())
