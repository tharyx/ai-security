"""Injecting a HARMLESS payload into a pickled "model", scanning it, and why safetensors is safer.

Everything here runs inside a temporary directory. The "malicious code" only writes a
canary file, so a test can prove whether code ran. Nothing touches the network or the
rest of the file system.

This file is self-contained. It follows the same idea as the scanner in
06-ai-devsecops/docker/lab/pickle_scan.py (opcode walk with pickletools, no loading) but
does not import it. Read that lab for the longer version (zip checkpoints, more cases).

Parts
    1. leave_canary / BoobyTrap     the harmless payload and the pickle that carries it
    2. scan_pickle_bytes()          list the globals a pickle would import, WITHOUT loading it
    3. RestrictedUnpickler          refuse non-allowlisted globals at load time (second layer)
    4. safetensors_dump / _load     a minimal data-only format (teaching re-implementation)
    5. safe_load_model()            the loading policy: prefer safetensors, scan, restrict
"""

from __future__ import annotations

import io
import json
import pickle
import pickletools
import struct
from dataclasses import dataclass, field
from pathlib import Path

CANARY_TEXT = "CANARY-injected-code-ran"

# ------------------------------------------------------------------------------------
# 1. The harmless payload
# ------------------------------------------------------------------------------------


def leave_canary(path: str) -> dict:
    """The 'malicious' payload: it only writes a canary file, then returns a normal-looking value."""
    Path(path).write_text(CANARY_TEXT, encoding="utf-8")
    return {"layer.weight": [0.0]}


class BoobyTrap:
    """Pickles as 'import leave_canary and call it with the path'. That is all __reduce__ does."""

    def __init__(self, canary_path: str) -> None:
        self.canary_path = canary_path

    def __reduce__(self):
        return (leave_canary, (self.canary_path,))


def make_state_dict() -> dict[str, list[float]]:
    return {"layer1.weight": [0.5, -0.25, 0.125, 1.0], "layer1.bias": [0.1, 0.2]}


def make_clean_pickle() -> bytes:
    return pickle.dumps(make_state_dict(), protocol=4)


def make_booby_trapped_pickle(canary_path: str) -> bytes:
    """A model file that looks like weights but also carries the payload."""
    sd: dict = make_state_dict()
    sd["_extra"] = BoobyTrap(canary_path)
    return pickle.dumps(sd, protocol=4)


# A hand-written pickle that REFERENCES os.system with an echo. It is only ever scanned,
# never loaded. It shows what a "DANGEROUS" verdict looks like.
NEVER_LOAD_OS_SYSTEM_PICKLE = b"cos\nsystem\n(S'echo scan-demo-only'\ntR."

# ------------------------------------------------------------------------------------
# 2. Static scan (no loading)
# ------------------------------------------------------------------------------------

SAFE_GLOBALS = {
    "collections.OrderedDict", "builtins.set", "builtins.frozenset", "builtins.bytearray",
    "numpy.core.multiarray._reconstruct", "numpy.ndarray", "numpy.dtype",
}
DANGEROUS_MODULES = {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy",
                     "importlib", "ctypes", "pty", "webbrowser", "urllib", "requests"}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "input"}
STRING_OPS = {"UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"}
CALL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"}


@dataclass
class ScanResult:
    verdict: str                      # SAFE | UNSAFE | DANGEROUS
    globals: list[str] = field(default_factory=list)
    calls: int = 0
    errors: list[str] = field(default_factory=list)


def is_dangerous(full_name: str) -> bool:
    module, _, name = full_name.rpartition(".")
    if module == "builtins":
        return name in DANGEROUS_BUILTINS
    return module.split(".")[0] in DANGEROUS_MODULES


def scan_pickle_bytes(data: bytes) -> ScanResult:
    """Walk the opcodes with pickletools.genops (decode only, never executes)."""
    res = ScanResult("SAFE")
    memo: dict[int, str] = {}
    strings: list[str] = []          # most recent pushed strings, newest last
    last_string: str | None = None
    try:
        for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
            name = op.name
            if name in STRING_OPS:
                strings.append(arg)
                last_string = arg
            elif name == "MEMOIZE":
                memo[len(memo)] = last_string or ""
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                memo[arg] = last_string or ""
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                strings.append(memo.get(arg, ""))
                last_string = memo.get(arg, "")
            elif name == "GLOBAL":
                module, _, attr = str(arg).partition(" ")
                res.globals.append(f"{module}.{attr}")
            elif name == "STACK_GLOBAL":
                if len(strings) >= 2 and strings[-1] and strings[-2]:
                    res.globals.append(f"{strings[-2]}.{strings[-1]}")
                else:
                    res.errors.append("could not resolve a STACK_GLOBAL; treat as unsafe")
            elif name in CALL_OPS:
                res.calls += 1
    except Exception as exc:  # malformed stream: do not guess
        res.errors.append(f"parse error: {exc}")
    if any(is_dangerous(g) for g in res.globals):
        res.verdict = "DANGEROUS"
    elif res.errors or any(g not in SAFE_GLOBALS for g in res.globals):
        res.verdict = "UNSAFE"
    return res


# ------------------------------------------------------------------------------------
# 3. Restricted unpickler (second layer)
# ------------------------------------------------------------------------------------


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str):
        if f"{module}.{name}" not in SAFE_GLOBALS:
            raise pickle.UnpicklingError(f"global not allowed: {module}.{name}")
        return super().find_class(module, name)


def restricted_loads(data: bytes):
    return RestrictedUnpickler(io.BytesIO(data)).load()


# ------------------------------------------------------------------------------------
# 4. A minimal safetensors-style format (data only)
# ------------------------------------------------------------------------------------


def safetensors_dump(tensors: dict[str, list[float]], metadata: dict[str, str] | None = None) -> bytes:
    """[8-byte little-endian header size][JSON header][raw float32 data]. Teaching version."""
    header: dict = {}
    if metadata:
        header["__metadata__"] = metadata
    blob = b""
    for name, values in tensors.items():
        raw = struct.pack(f"<{len(values)}f", *values)
        header[name] = {"dtype": "F32", "shape": [len(values)], "data_offsets": [len(blob), len(blob) + len(raw)]}
        blob += raw
    head = json.dumps(header, separators=(",", ":")).encode()
    head += b" " * (-len(head) % 8)
    return struct.pack("<Q", len(head)) + head + blob


def safetensors_load(data: bytes) -> dict[str, list[float]]:
    """Parse and validate. Raises ValueError on anything odd. Nothing here can run code."""
    if len(data) < 8:
        raise ValueError("too short")
    (hlen,) = struct.unpack("<Q", data[:8])
    if hlen > len(data) - 8 or hlen > 100_000_000:
        raise ValueError("bad header length")
    try:
        header = json.loads(data[8:8 + hlen])
    except json.JSONDecodeError as exc:
        raise ValueError("header is not JSON") from exc
    blob = data[8 + hlen:]
    out: dict[str, list[float]] = {}
    for name, info in header.items():
        if name == "__metadata__":
            continue
        if info.get("dtype") != "F32":
            raise ValueError(f"unsupported dtype for {name}")
        start, end = info["data_offsets"]
        if not (0 <= start <= end <= len(blob)) or (end - start) % 4:
            raise ValueError(f"bad offsets for {name}")
        out[name] = list(struct.unpack(f"<{(end - start) // 4}f", blob[start:end]))
    return out


# ------------------------------------------------------------------------------------
# 5. The loading policy
# ------------------------------------------------------------------------------------


class RefusedModel(Exception):
    pass


def naive_load(path: str):
    """What a careless script does. Never use this on a file you do not trust."""
    return pickle.loads(Path(path).read_bytes())


def safe_load_model(path: str, *, prefer_safetensors: bool = True, scan: bool = True, restricted: bool = True):
    data = Path(path).read_bytes()
    if prefer_safetensors and path.endswith(".safetensors"):
        return safetensors_load(data)             # data only: nothing to execute
    if scan:
        result = scan_pickle_bytes(data)
        if result.verdict != "SAFE":
            raise RefusedModel(f"{result.verdict}: {result.globals or result.errors}")
    return restricted_loads(data) if restricted else pickle.loads(data)
