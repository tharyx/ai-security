"""Shell tools. No shell, an argument list, and a strict allowlist pattern for each value."""

import re
import subprocess

from .errors import ToolInputError

_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}")
_NAME = re.compile(r"[A-Za-z0-9_]{1,40}")


def ping_host(host: str) -> str:
    if not _HOST.fullmatch(host):
        raise ToolInputError("invalid host")
    result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=5)
    return result.stdout


def archive_logs(name: str) -> str:
    if not _NAME.fullmatch(name):
        raise ToolInputError("invalid archive name")
    subprocess.run(["tar", "czf", f"{name}.tgz", "logs"], shell=False, timeout=30)
    return f"archived {name}.tgz"
