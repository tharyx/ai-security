"""Checks for userns-remap, the TCP socket without TLS, and the fd:// socket.

Inputs are fixtures: daemon.json, /etc/subuid + /etc/subgid text, a docker.socket unit
file and a client-certificate description. Nothing connects to anything.
"""
from __future__ import annotations

import configparser
from datetime import date


def check_userns(daemon: dict, subuid: str, subgid: str) -> list[str]:
    """userns-remap makes container root map to an unprivileged host UID range."""
    out = []
    remap = daemon.get("userns-remap")
    if not remap:
        return ["userns-remap not configured: container root is host root (UID 0)"]
    user = "dockremap" if remap == "default" else remap.split(":")[0]
    for label, text in (("subuid", subuid), ("subgid", subgid)):
        rows = [l.split(":") for l in text.splitlines() if l.strip() and not l.startswith("#")]
        mine = [r for r in rows if r[0] == user]
        if not mine:
            out.append(f"/etc/{label} has no range for {user}: daemon will fail to start")
        elif int(mine[0][2]) < 65536:
            out.append(f"/etc/{label} range for {user} is {mine[0][2]} (< 65536): too small for most images")
    return out


def check_tcp(daemon: dict) -> list[tuple[str, str]]:
    """Return (severity, message) for every tcp:// listener."""
    out = []
    tls_ok = all(daemon.get(k) for k in ("tlsverify", "tlscacert", "tlscert", "tlskey"))
    for h in daemon.get("hosts", []):
        if not h.startswith("tcp://"):
            continue
        addr = h[6:]
        public = addr.startswith(("0.0.0.0", "[::]", ":"))
        if not tls_ok and daemon.get("tls") is not True:
            out.append(("critical", f"{h}: Docker API on TCP without TLS: anyone reaching it is root on the host"))
        elif not tls_ok:
            out.append(("high", f"{h}: tls only (server auth): clients are not authenticated, need tlsverify + CA"))
        elif public:
            out.append(("medium", f"{h}: mutual TLS is on but bound to all interfaces: restrict by firewall or bind privately"))
        if addr.endswith(":2375") and not tls_ok:
            out.append(("critical", "port 2375 is the conventional plaintext Docker port"))
    return out


def check_fd(daemon: dict, socket_unit: str) -> list[str]:
    """fd:// = systemd opens the socket (docker.socket) and hands the file descriptor to dockerd."""
    out = []
    if "fd://" not in daemon.get("hosts", []):
        out.append("daemon does not use fd:// (systemd socket activation): socket permissions are managed by hand")
        return out
    cp = configparser.ConfigParser(strict=False)
    cp.optionxform = str
    cp.read_string(socket_unit)
    sock = cp["Socket"] if cp.has_section("Socket") else {}
    if sock.get("SocketMode") not in ("0660", "0600"):
        out.append(f"docker.socket SocketMode={sock.get('SocketMode')}: use 0660 (or 0600)")
    if sock.get("SocketGroup") in (None, "root") and sock.get("SocketMode") == "0660":
        out.append("SocketGroup should be 'docker' (a dedicated, audited group)")
    if any(k.startswith("ListenStream") and sock[k].startswith(("0.0.0.0", "[::]")) for k in sock):
        out.append("docker.socket listens on a TCP address")
    return out


def check_client_cert(cert: dict, allow_cns: set[str], today: date) -> list[str]:
    """Mutual TLS: the daemon verifies the CLIENT certificate too."""
    out = []
    if cert["cn"] not in allow_cns:
        out.append(f"client CN {cert['cn']} not in the allow list")
    if date.fromisoformat(cert["not_after"]) < today:
        out.append(f"client certificate expired {cert['not_after']}")
    if cert.get("issuer") != "dso-docker-ca":
        out.append(f"issuer {cert.get('issuer')} is not the daemon's CA")
    if "clientAuth" not in cert.get("eku", []):
        out.append("certificate lacks the clientAuth extended key usage")
    return out
