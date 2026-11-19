"""Web tool. DELIBERATELY VULNERABLE: it fetches any URL the model asks for (SSRF)."""

import urllib.request


def fetch_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(2000).decode("utf-8", "replace")
