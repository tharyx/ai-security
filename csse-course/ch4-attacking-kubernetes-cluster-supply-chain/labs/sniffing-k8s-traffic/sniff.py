"""Cleartext service-to-service traffic inside a cluster, and what mTLS changes (conceptual, offline).

A "capture" is a JSON list of flows: {src, dst, port, proto, tls, payload}. Payload text is only visible when the
flow is NOT encrypted. All secrets in the fixture are FAKE. The point: by default pod-to-pod traffic is plain unless
the application or a service mesh encrypts it. Anyone who can capture on the path (a pod with NET_RAW on a shared
node network, a compromised node, a hostNetwork pod, a tap) reads it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

PATTERNS = {
    "bearer-token": re.compile(r"Authorization:\s*Bearer\s+(\S+)", re.I),
    "basic-auth": re.compile(r"Authorization:\s*Basic\s+(\S+)", re.I),
    "password-field": re.compile(r"password=([^&\s]+)", re.I),
    "api-key": re.compile(r"(?:x-api-key|api_key)[:=]\s*(\S+)", re.I),
    "redis-auth": re.compile(r"^AUTH\s+(\S+)", re.M),
    "session-cookie": re.compile(r"Cookie:\s*[^\n]*?(sessionid|session)=([^;\s]+)", re.I),
}


@dataclass(frozen=True)
class Exposure:
    flow: str
    kind: str
    redacted: str


def load(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())["flows"]


def _redact(value: str) -> str:
    return value[:4] + "..." + f"({len(value)} chars)" if len(value) > 6 else "***"


def find_exposures(flows: list[dict]) -> list[Exposure]:
    out = []
    for f in flows:
        if f.get("tls") or f.get("mtls"):
            continue  # ciphertext: a sniffer sees only metadata (who talks to whom, how much)
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(f.get("payload", "")):
                out.append(Exposure(f"{f['src']} -> {f['dst']}:{f['port']}", kind, _redact(m.group(m.lastindex))))
    return out


def metadata_visible(flows: list[dict]) -> list[str]:
    """Even encrypted flows leak who talks to whom. mTLS hides content, not the existence of traffic."""
    return sorted({f"{f['src']} -> {f['dst']}:{f['port']}" for f in flows})


def apply_mesh(flows: list[dict], peer_auth: dict) -> list[dict]:
    """Simulate a service mesh PeerAuthentication policy (Istio-style concept). STRICT encrypts in-mesh flows; PERMISSIVE does not force it."""
    mode = (peer_auth.get("spec", {}).get("mtls") or {}).get("mode", "PERMISSIVE")
    meshed = set(peer_auth.get("meshed_workloads", []))
    out = []
    for f in flows:
        g = dict(f)
        if mode == "STRICT" and f["src"] in meshed and f["dst"] in meshed:
            g["mtls"] = True
        out.append(g)
    return out


def mtls_gaps(flows: list[dict], peer_auth: dict) -> list[str]:
    after = apply_mesh(flows, peer_auth)
    return [f"{f['src']} -> {f['dst']}:{f['port']}" for f in after if not f.get("tls") and not f.get("mtls")]


def can_sniff(pod: dict) -> tuple[bool, str]:
    """Can this pod capture packets? Needs NET_RAW (in the default container capability set unless dropped)."""
    spec = pod["spec"]
    for c in spec.get("containers", []):
        caps = (c.get("securityContext") or {}).get("capabilities") or {}
        if "ALL" in (caps.get("drop") or []) or "NET_RAW" in (caps.get("drop") or []):
            continue
        scope = "the whole node network" if spec.get("hostNetwork") else "its own pod network namespace (plus anything the CNI exposes)"
        return True, f"container {c['name']} keeps NET_RAW; can capture {scope}"
    return False, "NET_RAW is dropped in every container"
