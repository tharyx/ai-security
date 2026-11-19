"""Offline TLS configuration analysis.

The input is a JSON description of what a scanner (testssl.sh, sslyze, nmap ssl-enum-ciphers)
observed: protocol versions, cipher suites, the certificate, a few headers. No sockets are opened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

OLD_PROTOCOLS = {"SSLv2": "Critical", "SSLv3": "High", "TLSv1.0": "High", "TLSv1.1": "Medium"}
WEAK_CIPHER_PARTS = {
    "NULL": "Critical", "EXPORT": "Critical", "anon": "Critical", "RC4": "High",
    "3DES": "High", "DES": "High", "MD5": "High",
}
WEAK_SIGS = ("md5", "sha1")


@dataclass(frozen=True)
class TlsFinding:
    rule: str
    severity: str
    detail: str


def hostname_matches(host: str, names: list) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True  # a wildcard covers exactly one label
    return False


def analyze(cfg: dict, today: date | None = None) -> list:
    today = today or date.today()
    out: list = []
    protos = cfg.get("protocols", [])
    for p in protos:
        if p in OLD_PROTOCOLS:
            out.append(TlsFinding("TLS-OLD-PROTOCOL", OLD_PROTOCOLS[p], f"{p} is enabled"))
    if "TLSv1.3" not in protos:
        out.append(TlsFinding("TLS-NO-13", "Low", "TLS 1.3 is not offered"))
    for c in cfg.get("ciphers", []):
        for part, sev in WEAK_CIPHER_PARTS.items():
            if re.search(rf"(?<![A-Za-z]){part}(?![A-Za-z])", c):
                out.append(TlsFinding("TLS-WEAK-CIPHER", sev, f"{c} (contains {part})"))
                break
        else:
            if "_CBC_" in c:
                out.append(TlsFinding("TLS-CBC-CIPHER", "Low", f"{c} uses CBC mode (prefer AEAD: GCM or ChaCha20)"))
        if c.startswith("TLS_RSA_WITH_"):
            out.append(TlsFinding("TLS-NO-FORWARD-SECRECY", "Medium", f"{c} has no forward secrecy"))
    cert = cfg.get("cert") or {}
    if cert:
        na = date.fromisoformat(cert["not_after"])
        nb = date.fromisoformat(cert["not_before"])
        if na < today:
            out.append(TlsFinding("CERT-EXPIRED", "High", f"expired on {na}"))
        elif (na - today).days <= 30:
            out.append(TlsFinding("CERT-EXPIRING", "Medium", f"expires in {(na - today).days} days"))
        if nb > today:
            out.append(TlsFinding("CERT-NOT-YET-VALID", "High", f"valid from {nb}"))
        if cert.get("issuer", "").replace("CN=", "") == cert.get("subject_cn"):
            out.append(TlsFinding("CERT-SELF-SIGNED", "High", "issuer equals subject: no trusted CA in the chain"))
        names = cert.get("san") or [cert.get("subject_cn", "")]
        if not hostname_matches(cfg["host"], names):
            out.append(TlsFinding("CERT-HOSTNAME-MISMATCH", "High", f"{cfg['host']} not in {names}"))
        if cert.get("key_type") == "RSA" and cert.get("key_bits", 0) < 2048:
            out.append(TlsFinding("CERT-WEAK-KEY", "High", f"RSA {cert['key_bits']} bits"))
        if any(w in cert.get("sig_alg", "").lower() for w in WEAK_SIGS):
            out.append(TlsFinding("CERT-WEAK-SIGNATURE", "Medium", cert["sig_alg"]))
    hdrs = {k.lower(): v for k, v in cfg.get("http_headers", {}).items()}
    if "strict-transport-security" not in hdrs:
        out.append(TlsFinding("HSTS-MISSING", "Medium", "no Strict-Transport-Security header"))
    else:
        m = re.search(r"max-age=(\d+)", hdrs["strict-transport-security"])
        if not m or int(m.group(1)) < 15552000:
            out.append(TlsFinding("HSTS-SHORT", "Low", "max-age below 180 days"))
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(out, key=lambda f: (order[f.severity], f.rule))


def grade(findings: list) -> str:
    sev = {f.severity for f in findings}
    if "Critical" in sev:
        return "F"
    if "High" in sev:
        return "D"
    if "Medium" in sev:
        return "B"
    return "A" if not findings else "A-"
