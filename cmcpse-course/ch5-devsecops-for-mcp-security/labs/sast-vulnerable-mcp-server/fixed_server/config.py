"""Server settings. Secrets come from the environment, the bind is local only."""

import os

HOST = "127.0.0.1"
PORT = 8808
NOTES_DIR = "notes"
ALLOWED_HOSTS = frozenset({"example.com", "docs.example.com"})

API_KEY = os.environ.get("NOTES_API_KEY", "")
