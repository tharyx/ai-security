"""DNS log analyzer: tunneling, DGA-like names, and high NXDOMAIN rates.

Log line format (CSV): timestamp,client_ip,query_name,rcode   (rcode is NOERROR or NXDOMAIN)

Ideas:
  * DNS tunneling hides data in long, random-looking subdomains of one domain.
  * DGA (domain generation algorithm) malware tries many random names; most do not exist,
    so the client shows many NXDOMAIN answers.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

__all__ = ["DnsQuery", "Alert", "parse_dns_log", "shannon_entropy", "registered_domain",
           "detect_tunneling", "detect_dga_names", "detect_nxdomain_rate", "analyze"]


@dataclass(frozen=True)
class DnsQuery:
    time: str
    client: str
    name: str
    rcode: str


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    subject: str
    detail: str


def parse_dns_log(text: str) -> list[DnsQuery]:
    out = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 4 or parts[0].lower() == "timestamp":
            continue
        out.append(DnsQuery(parts[0], parts[1], parts[2].lower().rstrip("."), parts[3].upper()))
    return out


def shannon_entropy(text: str) -> float:
    """Bits per character. English-like words are about 2.5-3.5; random strings are higher."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def registered_domain(name: str) -> str:
    """Last two labels (good enough for *.example). A real tool would use the public-suffix list."""
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _subdomain(name: str) -> str:
    labels = name.split(".")
    return ".".join(labels[:-2])


def detect_tunneling(queries: list[DnsQuery], min_unique: int = 10, min_avg_len: int = 25) -> list[Alert]:
    """Many unique, long subdomains under one domain from one client."""
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for q in queries:
        sub = _subdomain(q.name)
        if sub:
            groups[(q.client, registered_domain(q.name))].add(sub)
    alerts = []
    for (client, domain), subs in sorted(groups.items()):
        avg = sum(len(s) for s in subs) / len(subs)
        if len(subs) >= min_unique and avg >= min_avg_len:
            alerts.append(Alert("dns_tunneling", "high", client,
                                f"{len(subs)} unique subdomains of {domain}, average length {avg:.0f} characters"))
    return alerts


def detect_dga_names(queries: list[DnsQuery], min_len: int = 12, min_entropy: float = 3.3) -> list[Alert]:
    """Registered-domain label that is long and random-looking, queried by a client."""
    flagged: dict[tuple[str, str], float] = {}
    for q in queries:
        label = registered_domain(q.name).split(".")[0]
        if len(label) >= min_len and shannon_entropy(label) >= min_entropy:
            flagged[(q.client, registered_domain(q.name))] = shannon_entropy(label)
    # Group by client so the analyst gets one alert per host.
    per_client: dict[str, list[str]] = defaultdict(list)
    for (client, dom), _ in sorted(flagged.items()):
        per_client[client].append(dom)
    return [Alert("dga_like_names", "high", c, f"{len(d)} random-looking domains, e.g. {d[0]}")
            for c, d in sorted(per_client.items())]


def detect_nxdomain_rate(queries: list[DnsQuery], min_queries: int = 10, min_rate: float = 0.5) -> list[Alert]:
    totals: Counter = Counter()
    nx: Counter = Counter()
    for q in queries:
        totals[q.client] += 1
        nx[q.client] += q.rcode == "NXDOMAIN"
    return [Alert("high_nxdomain_rate", "medium", c,
                  f"{nx[c]} of {t} lookups failed ({nx[c] / t:.0%} NXDOMAIN)")
            for c, t in sorted(totals.items()) if t >= min_queries and nx[c] / t >= min_rate]


def analyze(queries: list[DnsQuery]) -> list[Alert]:
    return detect_tunneling(queries) + detect_dga_names(queries) + detect_nxdomain_rate(queries)
