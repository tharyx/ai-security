"""File tools. DELIBERATELY VULNERABLE: the path is joined but never canonicalized."""

import os

from . import config


def read_note(name: str) -> str:
    path = os.path.join(config.NOTES_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def list_notes() -> list:
    return sorted(os.listdir(config.NOTES_DIR))
