"""A mini DAST: crawl, probe, report. Loopback only (scope guard).

It only sends harmless markers: a unique string for reflection, a single quote for
error-based SQL injection, and GETs for well-known sensitive paths.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, urljoin, urlparse

MARKER = "<dsoXSS7731>"
SQL_ERRORS = (
    "sqlite error",
    "sqlite3.",
    "syntax error",
    "unrecognized token",
    "unterminated quoted string",
    "ora-0",
    "you have an error in your sql",
)
SENSITIVE = {"/.git/HEAD": "ref:", "/.env": "PASSWORD", "/backup.sql": "INSERT INTO"}
DIR_LIST = ("/files/", "/uploads/")
HEADERS = ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    url: str
    evidence: str


def only_loopback(base: str) -> None:
    host = urlparse(base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"scope guard: {host!r} is not loopback; refusing to scan")


class Prober:
    def __init__(self, base: str, headers: dict | None = None):
        only_loopback(base)
        self.base = base.rstrip("/")
        self.headers = dict(headers or {})
        self.requests_sent = 0

    # ---- transport
    def get(self, path_or_url: str):
        url = urljoin(self.base + "/", path_or_url)
        req = urllib.request.Request(url, headers=self.headers)
        self.requests_sent += 1
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode(errors="replace")

    # ---- discovery
    def spider(self, start: str = "/", limit: int = 30) -> set:
        """Follow <a href> links only (like a classic spider). JS-built URLs are invisible."""
        seen, todo = set(), [start]
        while todo and len(seen) < limit:
            path = todo.pop()
            if path in seen:
                continue
            seen.add(path)
            status, _, body = self.get(path)
            if status != 200:
                continue
            for href in re.findall(r"href='([^']+)'|href=\"([^\"]+)\"", body):
                link = href[0] or href[1]
                full = urlparse(urljoin(self.base + "/", link))
                if full.netloc == urlparse(self.base).netloc:
                    todo.append(full.path + (f"?{full.query}" if full.query else ""))
        return seen

    # ---- checks
    def check_headers(self, path="/") -> list:
        _, hdrs, _ = self.get(path)
        low = {k.lower() for k in hdrs}
        out = [Finding("MISSING-HEADER", "Low", self.base + path, f"{h} not set") for h in HEADERS if h.lower() not in low]
        server = hdrs.get("Server", "")
        if "/" in server and re.search(r"\d", server):
            out.append(Finding("VERSION-DISCLOSURE", "Low", self.base + path, "Server: " + server))
        return out

    def probe_param(self, url: str) -> list:
        out = []
        parsed = urlparse(url)
        for param in parse_qs(parsed.query, keep_blank_values=True):
            _, _, body = self.get(f"{parsed.path}?{param}={quote(MARKER)}")
            if MARKER in body:
                out.append(Finding("REFLECTED-XSS", "High", f"{self.base}{parsed.path}?{param}=", "marker reflected unescaped"))
            _, _, body = self.get(f"{parsed.path}?{param}={quote(chr(39))}")
            low = body.lower()
            hit = next((e for e in SQL_ERRORS if e in low), None)
            if hit:
                out.append(Finding("SQLI-ERROR", "High", f"{self.base}{parsed.path}?{param}=", f"database error string: {hit!r}"))
        return out

    def check_paths(self) -> list:
        out = []
        for path, needle in SENSITIVE.items():
            status, _, body = self.get(path)
            if status == 200 and needle.lower() in body.lower():
                out.append(Finding("EXPOSED-FILE", "High", self.base + path, f"{path} readable"))
        for path in DIR_LIST:
            status, _, body = self.get(path)
            if status == 200 and "index of" in body.lower():
                out.append(Finding("DIR-LISTING", "Medium", self.base + path, "directory listing enabled"))
        return out

    # ---- orchestration
    def scan(self, urls: list | None = None) -> list:
        """Scan the given URLs; with none given, spider the home page first."""
        targets = urls if urls is not None else sorted(self.spider())
        found = self.check_headers() + self.check_paths()
        for u in targets:
            if "?" in u:
                found += self.probe_param(u)
        return sorted(set(found), key=lambda f: (f.severity != "High", f.rule, f.url))

    @staticmethod
    def coverage(urls: list) -> set:
        """(path, parameter) pairs we can actually probe: the attack surface that was reached."""
        pairs = set()
        for u in urls:
            p = urlparse(u)
            for param in parse_qs(p.query, keep_blank_values=True):
                pairs.add((p.path, param))
        return pairs
