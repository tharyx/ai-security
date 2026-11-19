"""Auditor: static config checks plus live probes against the simulated gateway."""

from __future__ import annotations

import http.client
import json

PATCHED_VERSION = (2026, 2, 0)  # keep in sync with sim_gateway.PATCHED_VERSION (fictional)


def _parse_version(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def audit_config(cfg: dict) -> list[dict]:
    """Static findings. Each: id, severity, message, fix."""
    out = []

    def add(i, sev, msg, fix):
        out.append({"id": i, "severity": sev, "message": msg, "fix": fix})

    if cfg.get("bind") in ("0.0.0.0", "::", ""):
        add("GW-BIND", "high", "gateway is configured to listen on all interfaces", "bind to 127.0.0.1 (or a private interface behind a VPN/proxy)")
    if not cfg.get("auth_token"):
        add("GW-AUTH", "critical", "no auth token configured", "require a long random token on every request")
    if "*" in cfg.get("allowed_origins", []):
        add("GW-ORIGIN", "high", "any web origin is allowed (CORS wildcard)", "allow only the exact origins of your own UI")
    if cfg.get("expose_token_in_api"):
        add("GW-TOKEN-EXPOSED", "critical", "the session API returns the token to callers", "never return secrets from an API; deliver them out-of-band")
    try:
        if _parse_version(cfg.get("version", "0")) < PATCHED_VERSION:
            add("GW-VERSION", "high", f"version {cfg.get('version')} is older than the fixed release", "update to a release that includes the origin/token fix")
    except ValueError:
        add("GW-VERSION", "medium", "cannot parse version", "pin a known version")
    return out


def _get(port: int, path: str, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def probe_gateway(port: int) -> list[dict]:
    """Dynamic probes, as an anonymous web page on another origin would send them."""
    out = []
    evil = {"Origin": "http://evil.example"}
    status, headers, data = _get(port, "/api/session")
    if status == 200:
        out.append({"id": "PROBE-NOAUTH", "severity": "critical", "message": "session API answers without credentials"})
    status, headers, data = _get(port, "/api/session", evil)
    if status == 200 and headers.get("Access-Control-Allow-Origin") in ("*", "http://evil.example"):
        out.append({"id": "PROBE-CROSS-ORIGIN", "severity": "high", "message": "a foreign origin can read the response"})
    if status == 200 and "token" in data:
        out.append({"id": "PROBE-TOKEN-LEAK", "severity": "critical", "message": "a foreign origin obtained a token (simulated token theft)"})
    return out
