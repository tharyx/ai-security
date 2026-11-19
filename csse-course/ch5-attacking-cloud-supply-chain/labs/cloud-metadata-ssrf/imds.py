"""Simulated instance metadata services (in-process, no network) and a vulnerable URL-fetch app.

Everything here is a teaching model. Real header names and paths are hedged: verify in provider docs.
All credentials are FAKE.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

FAKE_AWS_CREDS = {
    "Code": "Success",
    "AccessKeyId": "ASIAFAKEFAKEFAKE0001",
    "SecretAccessKey": "FAKE/secret/key/not/real",
    "Token": "FAKE-SESSION-TOKEN",
}
METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}
METADATA_NAMES = {"metadata.google.internal", "metadata"}


@dataclass
class Request:
    method: str
    path: str
    headers: dict = field(default_factory=dict)
    hops: int = 1  # network hops from the instance (a container behind a bridge adds one)

    def header(self, name: str):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class AwsIMDS:
    """EC2-style IMDS. v2_required=False means IMDSv1 is still enabled (optional)."""

    def __init__(self, v2_required: bool = False, hop_limit: int = 1):
        self.v2_required = v2_required
        self.hop_limit = hop_limit
        self._tokens: set[str] = set()

    def handle(self, req: Request):
        if req.header("X-Forwarded-For"):  # proxied requests are rejected by design
            return 403, "forbidden: forwarded request"
        if req.method == "PUT" and req.path == "/latest/api/token":
            if req.hops > self.hop_limit:
                return 0, "dropped: response TTL expired (hop limit)"
            if not req.header("X-aws-ec2-metadata-token-ttl-seconds"):
                return 400, "missing ttl header"
            tok = secrets.token_hex(8)
            self._tokens.add(tok)
            return 200, tok
        if req.method != "GET":
            return 405, "method not allowed"
        if self.v2_required:
            if req.header("X-aws-ec2-metadata-token") not in self._tokens:
                return 401, "unauthorized: token required (IMDSv2)"
        if req.path == "/latest/meta-data/iam/security-credentials/":
            return 200, "web-role"
        if req.path == "/latest/meta-data/iam/security-credentials/web-role":
            return 200, json.dumps(FAKE_AWS_CREDS)
        return 404, "not found"


class AzureIMDS:
    def handle(self, req: Request):
        if req.header("X-Forwarded-For"):
            return 403, "forbidden: forwarded request"
        if (req.header("Metadata") or "").lower() != "true":
            return 400, "Required metadata header not specified"
        if req.path.startswith("/metadata/identity/oauth2/token"):
            return 200, json.dumps({"access_token": "FAKE-AZURE-TOKEN", "resource": "https://management.azure.example/"})
        if req.path.startswith("/metadata/instance"):
            return 200, json.dumps({"compute": {"name": "vm-demo", "location": "region-x"}})
        return 404, "not found"


class GcpMetadata:
    def handle(self, req: Request):
        if req.header("X-Forwarded-For"):
            return 403, "forbidden: forwarded request"
        if req.header("Metadata-Flavor") != "Google":
            return 403, "Missing Metadata-Flavor:Google header"
        if req.path == "/computeMetadata/v1/instance/service-accounts/default/token":
            return 200, json.dumps({"access_token": "FAKE-GCP-TOKEN", "expires_in": 3599})
        return 404, "not found"


class Network:
    """Routes a URL to a simulated metadata service or a harmless 'internet' page."""

    def __init__(self, aws=None, azure=None, gcp=None):
        self.aws, self.azure, self.gcp = aws, azure, gcp

    def request(self, method, url, headers=None, hops=1):
        u = urlparse(url)
        req = Request(method, u.path + (("?" + u.query) if u.query else ""), headers or {}, hops)
        host = (u.hostname or "").lower()
        if host == "169.254.169.254":
            if u.path.startswith("/latest") and self.aws:
                return self.aws.handle(req)
            if u.path.startswith("/metadata") and self.azure:
                return self.azure.handle(req)
            if u.path.startswith("/computeMetadata") and self.gcp:
                return self.gcp.handle(req)
        if host == "metadata.google.internal" and self.gcp:
            return self.gcp.handle(req)
        return 200, f"<html>public page {host}</html>"


def vulnerable_preview(net: Network, url: str, attacker_controls_headers=False, attacker_method="GET", hops=1):
    """A 'URL preview' feature: fetches whatever URL the user supplies (classic SSRF)."""
    headers = {"Metadata": "true", "Metadata-Flavor": "Google"} if attacker_controls_headers else {}
    return net.request(attacker_method, url, headers, hops)


def _host_addresses(host: str, resolver: dict):
    host = host.strip("[]").lower()
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:  # decimal or hex integer forms such as 2852039166 or 0xA9FEA9FE
        n = int(host, 0)
        if 0 <= n < 2**32:
            return [ipaddress.ip_address(n)]
    except ValueError:
        pass
    return [ipaddress.ip_address(a) for a in resolver.get(host, [])]


def is_blocked(url: str, resolver: dict | None = None) -> bool:
    """Deny check applied to the URL and to the *resolved* addresses."""
    resolver = resolver or {}
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return True
    host = u.hostname.lower()
    if host in METADATA_NAMES:
        return True
    addrs = _host_addresses(host, resolver)
    if not addrs:
        return True  # cannot resolve -> fail closed
    for a in addrs:
        if a.is_link_local or a.is_loopback or a.is_private or a.is_reserved or str(a) in METADATA_IPS:
            return True
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped and (a.ipv4_mapped.is_link_local or a.ipv4_mapped.is_private):
            return True
    return False


def safe_preview(net: Network, url: str, resolver: dict | None = None, redirects: list | None = None):
    """Fixed app: block internal targets, re-check every redirect hop."""
    chain = [url] + list(redirects or [])
    for hop in chain:
        if is_blocked(hop, resolver):
            return 403, f"blocked by egress policy: {hop}"
    return net.request("GET", chain[-1])
