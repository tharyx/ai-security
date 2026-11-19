"""File tools. The path is resolved (symlinks, ..) and must stay inside the notes directory."""

import os
from pathlib import Path

from . import config
from .errors import ToolInputError


def _safe_path(name: str) -> Path:
    base = Path(config.NOTES_DIR).resolve()
    try:
        target = (base / name).resolve()
    except (ValueError, OSError):
        raise ToolInputError("invalid note name") from None
    if not target.is_relative_to(base) or not target.is_file():
        raise ToolInputError("note not found")
    return target


def read_note(name: str) -> str:
    return _safe_path(name).read_text(encoding="utf-8")


def list_notes() -> list:
    return sorted(os.listdir(config.NOTES_DIR))
