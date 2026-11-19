"""Probe a list of LOCAL endpoints for an unauthenticated Docker API. Loopback only: any other target is refused.

Real-world note: scanning hosts you do not own is illegal in many places. This lab hard-codes the rule.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request


class RefusedTarget(Exception):
    pass


def check_target(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise RefusedTarget(f"{host!r} is not an IP literal; only 127.0.0.0/8 and ::1 are allowed") from None
    if not ip.is_loopback:
        raise RefusedTarget(f"{host} is not loopback: refusing to scan a host you do not own")


def _get(host: str, port: int, path: str, headers: dict | None = None, timeout: float = 2.0):
    req = urllib.request.Request(f"http://{host}:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, OSError):
        return None, ""


def probe(host: str, port: int) -> dict:
    check_target(host)
    result = {"endpoint": f"{host}:{port}", "state": "closed", "evidence": []}
    code, body = _get(host, port, "/_ping")
    if code is None:
        return result
    if code == 401:
        result.update(state="auth required", evidence=["/_ping -> 401"])
        return result
    if code == 200 and body.strip() == "OK":
        result["state"] = "UNAUTHENTICATED Docker API"
        result["evidence"].append("/_ping -> 200 OK without credentials")
        c2, b2 = _get(host, port, "/version")
        if c2 == 200:
            v = json.loads(b2)
            result["version"] = v.get("Version")
            result["evidence"].append(f"/version -> Docker {v.get('Version')} on {v.get('Os')}/{v.get('Arch')}")
        c3, b3 = _get(host, port, "/containers/json")
        if c3 == 200:
            cs = json.loads(b3)
            result["containers"] = [c["Names"][0].lstrip("/") for c in cs]
            result["evidence"].append(f"/containers/json -> {len(cs)} containers listed: {result['containers']}")
        result["impact"] = ("anyone who can reach this port can create a privileged container with the host root mounted: "
                            "treat it as root on the host")
        return result
    result.update(state="open, not a Docker API", evidence=[f"/_ping -> {code}"])
    return result


def scan(endpoints: list[tuple[str, int]]) -> list[dict]:
    out = []
    for host, port in endpoints:
        try:
            out.append(probe(host, port))
        except RefusedTarget as e:
            out.append({"endpoint": f"{host}:{port}", "state": "REFUSED", "evidence": [str(e)]})
    return out
