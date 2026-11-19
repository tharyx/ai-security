"""OWASP Top 10 issues in containerized apps, plus an SSRF-to-cloud-metadata demonstration (all in-process).

Part 1: the OWASP Top 10 (2021 edition; a newer edition may exist: verify at source) mapped to what each category
looks like when the app runs in a container, and where to practise it in this repo.
Part 2: a vulnerable 'fetch this URL' feature, a fake cloud metadata service at 169.254.169.254 (IMDS-style, v1 and v2
behaviour), and three defences. No sockets, no real metadata service: it is function calls on fake objects.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

TOP10 = [
    ("A01", "Broken Access Control", "Container exposes an admin UI/API on a published port; path traversal reads mounted host files.", "csse ch2 dynamic-analysis lab; cybersecurity-track 09"),
    ("A02", "Cryptographic Failures", "TLS keys baked into the image; secrets in env vars; plain HTTP between containers.", "extract-secrets-from-container"),
    ("A03", "Injection", "Command injection in an app running as root with docker.sock mounted becomes host compromise.", "container-escapes"),
    ("A04", "Insecure Design", "One flat network for every service; no limits; no threat model for the container boundary.", "daemon-and-kernel-attacks"),
    ("A05", "Security Misconfiguration", "Privileged mode, default credentials, debug mode in prod, exposed daemon/management UI.", "privilege-escalation-and-misconfig; portainer-attack"),
    ("A06", "Vulnerable and Outdated Components", "Old base images and unpatched libraries inside layers.", "image-based-attacks; recon-third-party-image-inspection"),
    ("A07", "Identification and Authentication Failures", "Default admin/admin on management tools and registries.", "registry-attacks; portainer-attack"),
    ("A08", "Software and Data Integrity Failures", "Unsigned images pulled by mutable tag; CI pushes unverified artifacts.", "csse ch3 backdoor-docker-image; container-registry (ch9)"),
    ("A09", "Security Logging and Monitoring Failures", "No docker events/audit logs; container logs lost on rm.", "inspect-daemon-activity"),
    ("A10", "Server-Side Request Forgery", "App fetches attacker URLs from inside the cloud network and reaches the metadata service.", "this lab (SSRF)"),
]

METADATA_IP = "169.254.169.254"
ROLE_PATH = "/latest/meta-data/iam/security-credentials/app-role"


def role_credentials() -> dict:
    """FAKE cloud credentials, a canary: not a real format."""
    return {"AccessKeyId": "CANARY-" + "ACCESS-" + "KEY-ID", "SecretAccessKey": "canary-" + "secret-" + "value", "Token": "canary-session-token"}


class MetadataService:
    """IMDS-style service. v1: any GET works. v2: needs a session token from a PUT; hop limit 1 stops containers."""

    def __init__(self, version: int = 1, hop_limit: int = 1):
        self.version, self.hop_limit = version, hop_limit
        self._token = "imds-session-canary"

    def put_token(self, from_container: bool) -> str | None:
        if self.version == 1:
            return None
        hops_needed = 2 if from_container else 1       # the extra bridge/NAT hop of a container
        return self._token if hops_needed <= self.hop_limit else None

    def get(self, path: str, token: str | None = None) -> tuple[int, dict | str]:
        if self.version == 2 and token != self._token:
            return 401, "Unauthorized (token required)"
        if path == ROLE_PATH:
            return 200, role_credentials()
        return 404, "not found"


def canonical_host(host: str) -> str:
    """Resolve odd IPv4 spellings (decimal/hex/octal integer forms) so filters compare the real address."""
    h = host.strip("[]")
    try:
        if h.lower().startswith("0x") and "." not in h:
            return str(ipaddress.ip_address(int(h, 16)))
        if h.isdigit():
            return str(ipaddress.ip_address(int(h)))
        return str(ipaddress.ip_address(h))
    except ValueError:
        return h


class VulnerableApp:
    """A feature like 'fetch a URL for a link preview'. `policy`: none | naive-blocklist | strict."""

    def __init__(self, metadata: MetadataService, policy: str = "none"):
        self.metadata, self.policy = metadata, policy

    def _allowed(self, url: str) -> tuple[bool, str]:
        u = urlparse(url)
        if self.policy == "none":
            return True, ""
        if self.policy == "naive-blocklist":
            if METADATA_IP in url:
                return False, "blocked by string match"
            return True, ""
        host = canonical_host(u.hostname or "")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return (u.scheme == "https" and host in ("images.example.net",)), "host not on the allow-list"
        if ip.is_link_local or ip.is_private or ip.is_loopback or ip.is_reserved:
            return False, f"{ip} is an internal address"
        return True, ""

    def fetch(self, url: str) -> tuple[int, object]:
        ok, why = self._allowed(url)
        if not ok:
            return 403, f"blocked: {why}"
        u = urlparse(url)
        if canonical_host(u.hostname or "") == METADATA_IP:
            # the app can only send a plain GET: no custom header, no PUT, so it has no v2 token
            return self.metadata.get(u.path, token=None)
        return 200, "<html>external page</html>"


def ssrf_matrix() -> list[tuple[str, str, int]]:
    """(scenario, url, status) for a set of URLs against each defence."""
    urls = [("direct", f"http://{METADATA_IP}{ROLE_PATH}"),
            ("decimal IP trick", f"http://2852039166{ROLE_PATH}"),
            ("legit", "https://images.example.net/logo.png")]
    rows = []
    for label, md, policy in [("IMDSv1, no filter", MetadataService(1), "none"), ("IMDSv1, naive blocklist", MetadataService(1), "naive-blocklist"),
                              ("IMDSv1, strict filter", MetadataService(1), "strict"), ("IMDSv2 (token + hop limit 1), no filter", MetadataService(2), "none")]:
        app = VulnerableApp(md, policy)
        for name, url in urls:
            rows.append((f"{label} / {name}", url, app.fetch(url)[0]))
    return rows
