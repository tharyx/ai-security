"""Web tool. https only, exact-host allowlist, no raw IP addresses."""

import ipaddress
import urllib.parse
import urllib.request

from . import config
from .errors import ToolInputError


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https":
        raise ToolInputError("only https is allowed")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ToolInputError("IP addresses are not allowed")
    if host not in config.ALLOWED_HOSTS:
        raise ToolInputError("host is not allowed")


def fetch_url(url: str) -> str:
    _check_url(url)
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(2000).decode("utf-8", "replace")
