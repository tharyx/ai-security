"""Build a folder of harmless "model" files for the exercise.

The malicious-STYLE files are hand-written pickle bytes. Their "command" is ``echo CANARY``.
They are only ever scanned. Nothing in this lab loads (unpickles) them.

Opcode cheat sheet: c = GLOBAL, \\x93 = STACK_GLOBAL, R = REDUCE (call), . = STOP.
"""

from __future__ import annotations

import io
import json
import pickle
import struct
import zipfile
from pathlib import Path

EVIL_PROTOCOL0 = b"cos\nsystem\n(S'echo CANARY'\ntR."
EVIL_STACK_GLOBAL = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x94\x93\x8c\x0becho CANARY\x94\x85R."
EVIL_MEMO_TRICK = (b"\x80\x04\x8c\x02os\x940\x8c\x08harmless\x940h\x00\x8c\x06system\x94\x93"
                   b"\x8c\x0becho CANARY\x94\x85R.")
EVIL_BROKEN = b"cos\nsystem\n(S'echo CANARY'\ntR" + b"\xff\xff"
UNKNOWN_GADGET = b"\x80\x04\x8c\x06timeit\x94\x8c\x06timeit\x94\x93\x8c\x04pass\x94\x85R."


def safetensors_bytes() -> bytes:
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}).encode()
    return struct.pack("<Q", len(header)) + header + struct.pack("<2f", 0.5, 1.5)


def zip_with(inner: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", inner)
        z.writestr("archive/version", "3\n")
    return buf.getvalue()


def build(folder: str | Path) -> dict[str, str]:
    """Write the samples; return {filename: expected verdict}."""
    folder = Path(folder)
    files = {
        "clean_weights.pkl": (pickle.dumps({"layer1": [0.1, 0.2]}), "SAFE"),
        "weights.safetensors": (safetensors_bytes(), "SAFE"),
        "evil_protocol0.pkl": (EVIL_PROTOCOL0, "DANGEROUS"),
        "evil_stack_global.pkl": (EVIL_STACK_GLOBAL, "DANGEROUS"),
        "evil_memo_trick.pkl": (EVIL_MEMO_TRICK, "DANGEROUS"),
        "evil_broken_stream.pkl": (EVIL_BROKEN, "DANGEROUS"),
        "unknown_gadget.pkl": (UNKNOWN_GADGET, "SUSPICIOUS"),
        "evil_inside_model.pt": (zip_with(EVIL_STACK_GLOBAL), "DANGEROUS"),
    }
    for name, (data, _) in files.items():
        (folder / name).write_bytes(data)
    return {name: verdict for name, (_, verdict) in files.items()}
