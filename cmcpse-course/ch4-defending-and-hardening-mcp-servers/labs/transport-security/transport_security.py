"""Transport security helpers for MCP: TLS contexts, SPKI pinning, Origin/Host checks, safe binding, stdio launch hygiene.

Covers the chapter 4 "Transport Security" topics with small, testable functions:
    client_context()        Python ssl context basics: verify certificates AND hostnames, TLS 1.2+ only
    spki_sha256()           pin the public key (SPKI hash), not the whole certificate, so renewals with the same key keep working
    connect_pinned()        TLS connect that checks the pin after the normal validation
    check_request_origin()  DNS rebinding and CSRF defence for HTTP servers on localhost (Host and Origin header checks)
    safe_bind_address()     refuse 0.0.0.0 unless an operator opted in
    stdio_env()             a minimal environment for a stdio child process (no inherited secrets)
    audit_launch_config()   flag risky command lines in an mcp.json style host config

Pinning is an extra layer on top of normal validation, never a replacement. Never disable verification
(CERT_NONE, check_hostname=False, verify=False) to "make it work".
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import socket
import ssl
from typing import Any, Iterable


# ---------------------------------------------------------------------------------- TLS basics

def client_context(cafile: str | None = None) -> ssl.SSLContext:
    """A client context that does the right things by default. ``cafile`` adds a private CA (internal servers)."""
    ctx = ssl.create_default_context(cafile=cafile)       # loads the system CAs, CERT_REQUIRED, check_hostname=True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    return ctx


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


# ---------------------------------------------------------------------------------- SPKI pinning

def _tlv(data: bytes, off: int) -> tuple[int, int, int]:
    """Read one DER element at ``off``. Returns (tag, content_start, content_end)."""
    tag = data[off]
    length = data[off + 1]
    pos = off + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def spki_der(cert_der: bytes) -> bytes:
    """Extract the SubjectPublicKeyInfo (DER) from an X.509 certificate (DER) with a tiny parser."""
    _, cert_start, _ = _tlv(cert_der, 0)                  # Certificate ::= SEQUENCE
    _, tbs_start, tbs_end = _tlv(cert_der, cert_start)    # tbsCertificate ::= SEQUENCE
    off, idx = tbs_start, 0
    first_tag = cert_der[off]
    spki_index = 6 if first_tag == 0xA0 else 5            # [0] version is optional; then serial, sigAlg, issuer, validity, subject, spki
    while off < tbs_end:
        tag, c_start, c_end = _tlv(cert_der, off)
        if idx == spki_index:
            return cert_der[off:c_end]
        off, idx = c_end, idx + 1
    raise ValueError("SubjectPublicKeyInfo not found")


def spki_sha256(cert_der: bytes) -> str:
    """base64(SHA-256(SPKI)). The same format used by the old HPKP header and by curl --pinnedpubkey sha256//..."""
    return base64.b64encode(hashlib.sha256(spki_der(cert_der)).digest()).decode()


def pin_matches(cert_der: bytes, pins: Iterable[str]) -> bool:
    return spki_sha256(cert_der) in set(pins)


def connect_pinned(host: str, port: int, ctx: ssl.SSLContext, pins: Iterable[str], timeout: float = 3.0) -> str:
    """Open a TLS connection with normal validation, then require the server key to be pinned. Returns the TLS version."""
    pins = list(pins)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der or not pin_matches(der, pins):
                raise ssl.SSLError("server public key does not match any pinned SPKI hash")
            return tls.version() or ""


# ---------------------------------------------------------------------------------- HTTP server on localhost

def check_request_origin(headers: dict[str, str], allowed_hosts: Iterable[str], allowed_origins: Iterable[str]) -> tuple[bool, str]:
    """Validate Host and Origin for an HTTP MCP server bound to localhost.

    * DNS rebinding: a web page at evil.example gets its name re-resolved to 127.0.0.1. The browser then sends
      ``Host: evil.example``, so the server must reject any Host it does not own.
    * Cross-site requests: browsers send ``Origin`` on cross-origin requests. If present it must be allowed.
      A missing Origin is normal for non-browser clients (the CLI, the SDK), so it is allowed here, but then
      authentication must still be required (see defend-oauth-scopes).
    """
    h = {k.lower(): v for k, v in headers.items()}
    host = h.get("host", "").lower()
    if host not in {x.lower() for x in allowed_hosts}:
        return False, f"host {host!r} not allowed"
    origin = h.get("origin")
    if origin is not None and origin.lower() not in {x.lower() for x in allowed_origins}:
        return False, f"origin {origin!r} not allowed"
    return True, "ok"


def safe_bind_address(host: str, allow_external: bool = False) -> str:
    """Return the host if it is loopback (or an operator allowed external binding); otherwise raise."""
    if host in ("localhost",):
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{host!r} is not an IP address or localhost") from exc
    if ip.is_loopback:
        return host
    if ip.is_unspecified or not allow_external:
        raise ValueError(f"refusing to bind {host}: listens on every interface. Use 127.0.0.1, or set allow_external with TLS and auth")
    return host


# ---------------------------------------------------------------------------------- stdio

SAFE_ENV_KEYS = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "LANG", "TERM")


def stdio_env(parent_env: dict[str, str], extra: dict[str, str] | None = None, allow: Iterable[str] = SAFE_ENV_KEYS) -> dict[str, str]:
    """Build the environment for a stdio server. Do not pass the parent environment: it holds cloud keys and tokens."""
    env = {k: v for k, v in parent_env.items() if k in set(allow)}
    env.update(extra or {})
    return env


SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
SECRET_NAME = re.compile(r"(?i)(key|secret|token|passw)")
SECRET_VALUE = re.compile(r"(sk-[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|hvs\.[A-Za-z0-9_-]{12,})")


def audit_launch_config(config: dict[str, Any]) -> list[dict[str, str]]:
    """Check an ``{"mcpServers": {name: {command, args, env}}}`` config for risky launch lines."""
    findings: list[dict[str, str]] = []

    def add(server: str, rule: str, detail: str) -> None:
        findings.append({"server": server, "rule": rule, "detail": detail})

    for name, spec in (config.get("mcpServers") or {}).items():
        cmd = str(spec.get("command", ""))
        args = [str(a) for a in spec.get("args", [])]
        base = re.split(r"[\\/]", cmd)[-1].lower()
        line = " ".join([cmd, *args])
        if base in SHELLS:
            add(name, "shell_wrapper", "launches through a shell: arguments are parsed by the shell (injection risk)")
        if re.search(r"(curl|wget)\b.*\|\s*(sh|bash)", line):
            add(name, "pipe_to_shell", "downloads and runs code in one line")
        if base in ("npx", "npx.cmd") and not any(re.search(r"@\d+\.\d+\.\d+", a) for a in args):
            add(name, "unpinned_package", "npx without an exact version runs whatever is latest (rug pull and typosquat risk)")
        if base in ("uvx", "pipx") and not any(re.search(r"(==|@)\d+\.\d+", a) for a in args):
            add(name, "unpinned_package", f"{base} without an exact version")
        if cmd and not (cmd.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", cmd)) and not re.match(r"^[A-Za-z0-9_.-]+$", cmd):
            add(name, "relative_command", "relative path: which program runs depends on the working directory")
        for k, v in (spec.get("env") or {}).items():
            if SECRET_VALUE.search(str(v)) or (SECRET_NAME.search(k) and not str(v).startswith("${")):
                add(name, "inline_secret", f"env {k} holds a literal secret in the config file; reference a secret store instead")
        if any(re.search(r"(http://(?!127\.0\.0\.1|localhost))", a) for a in args):
            add(name, "plain_http", "points at a non-local http:// URL")
        if "0.0.0.0" in line:
            add(name, "binds_all_interfaces", "listens on every interface")
    return findings
