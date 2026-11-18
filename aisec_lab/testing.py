"""Small helpers shared by lab code and lab tests."""

from __future__ import annotations

import hashlib
import importlib.util
import secrets
import sys
from pathlib import Path
from types import ModuleType


def make_canary(label: str = "CANARY") -> str:
    """Return a unique fake secret, e.g. ``CANARY-9f2c4e1a7b``.

    Put canaries where real secrets would be (system prompts, documents, tool
    results). If one ever shows up in model output, logs or another tenant's
    response, you have proven a leak - without risking a real secret.
    """
    return f"{label}-{secrets.token_hex(5)}"


def load_lab_module(test_file: str, name: str) -> ModuleType:
    """Import ``<name>.py`` that sits next to ``test_file``, under a unique module name.

    Lab folders contain hyphens (``prompt-injection``), so they are not importable
    packages, and many labs reuse names like ``vulnerable_app.py``. Loading by path
    with a unique name avoids collisions. Use it in tests::

        app = load_lab_module(__file__, "vulnerable_app")
    """
    path = Path(test_file).resolve().with_name(f"{name}.py")
    digest = hashlib.sha1(str(path).encode()).hexdigest()[:10]
    unique = f"aisec_lab_{name}_{digest}"
    if unique in sys.modules:
        return sys.modules[unique]
    spec = importlib.util.spec_from_file_location(unique, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique] = module
    spec.loader.exec_module(module)
    return module
