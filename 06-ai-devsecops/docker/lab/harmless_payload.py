"""A HARMLESS stand-in for a malicious pickle payload.

Real malicious model files call things like ``os.system`` or open a reverse shell.
This lab never does that. Its "payload" only writes a canary file, so a test can
prove that code ran (file exists) or did not run (file missing).
"""

from __future__ import annotations

from pathlib import Path

CANARY_TEXT = "CANARY-pickle-payload-ran"


def leave_canary(path: str) -> str:
    Path(path).write_text(CANARY_TEXT, encoding="utf-8")
    return "model-weights-placeholder"


class BoobyTrappedModel:
    """Pickles to: 'import harmless_payload.leave_canary, then call it'."""

    def __init__(self, canary_path: str) -> None:
        self.canary_path = canary_path

    def __reduce__(self):
        return (leave_canary, (self.canary_path,))
