"""Notes server (clean)."""
import os
from pathlib import Path

NOTES = Path(os.environ.get("NOTES_DIR", "notes")).resolve()


def read_note(name):
    target = (NOTES / name).resolve()
    if not target.is_relative_to(NOTES):
        raise PermissionError("outside notes")
    return target.read_text()
