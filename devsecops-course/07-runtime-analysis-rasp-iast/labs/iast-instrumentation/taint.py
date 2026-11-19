"""Taint tracking for the toy IAST agent.

``TaintedStr`` is a ``str`` that remembers where its characters came from. When it is joined with
other text using ``+`` or a single ``%s``, the result is still tainted and remembers which parts came
from the request. This is the same idea a real agent implements inside the language runtime.

Known limits (on purpose, they are part of the lesson): f-strings, ``str.format`` and ``''.join``
build a plain ``str`` and drop the taint. A real agent hooks lower down (bytecode or runtime
internals) to avoid these gaps. Here we simply show the false negative.
"""

from __future__ import annotations

import os
import sys


def where(depth: int = 2) -> str:
    f = sys._getframe(depth)
    return f"{os.path.basename(f.f_code.co_filename)}:{f.f_code.co_name}:{f.f_lineno}"


class TaintedStr(str):
    parts: tuple   # ((text, origin_or_None), ...)  origin None means trusted literal text
    trail: tuple   # propagation steps, e.g. ("concat at tinyapp.py:user_by_name:41",)

    def __new__(cls, value, origin=None, parts=None, trail=()):
        obj = super().__new__(cls, value)
        obj.parts = parts if parts is not None else ((str(value), origin),)
        obj.trail = tuple(trail)
        return obj

    # ---- propagation
    def __add__(self, other):
        return TaintedStr(str(self) + str(other), parts=self.parts + _parts(other), trail=self.trail + _trail(other) + (f"concat at {where()}",))

    def __radd__(self, other):
        return TaintedStr(str(other) + str(self), parts=_parts(other) + self.parts, trail=_trail(other) + self.trail + (f"concat at {where()}",))

    def __rmod__(self, fmt):
        """``'... %s ...' % tainted`` (single placeholder)."""
        before, sep, after = str(fmt).partition("%s")
        if not sep:
            return str.__mod__(str(fmt), str(self))
        parts = ((before, None),) + self.parts + ((after, None),)
        return TaintedStr(before + str(self) + after, parts=parts, trail=self.trail + (f"%s format at {where()}",))

    def strip(self, *a):
        return TaintedStr(str.strip(self, *a), parts=((str.strip(self, *a), self.origin),), trail=self.trail + (f"strip at {where()}",))

    def lower(self):
        return TaintedStr(str.lower(self), parts=((str.lower(self), self.origin),), trail=self.trail + (f"lower at {where()}",))

    # ---- queries
    @property
    def origin(self):
        return next((o for _, o in self.parts if o), None)

    def tainted_text(self) -> list:
        return [(t, o) for t, o in self.parts if o]


def _parts(x):
    return x.parts if isinstance(x, TaintedStr) else ((str(x), None),)


def _trail(x):
    return x.trail if isinstance(x, TaintedStr) else ()


def is_tainted(x) -> bool:
    return isinstance(x, TaintedStr) and any(o for _, o in x.parts)


def sanitize_int(x) -> int:
    """A sanitizer: converting to int removes the taint (and raises on anything non-numeric)."""
    return int(str(x))
