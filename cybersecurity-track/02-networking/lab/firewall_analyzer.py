"""Firewall log analyzer: port scans, denied-traffic spikes, traffic to rare ports.

Log line format (simple, vendor-neutral):
    2026-11-02T09:00:01Z DENY TCP 203.0.113.9:44012 -> 192.0.2.10:22
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

__all__ = ["FwEvent", "Alert", "parse_firewall_log", "detect_port_scans",
           "detect_denied_spikes", "detect_rare_ports", "analyze", "COMMON_PORTS"]

_LINE = re.compile(r"^(?P<ts>\S+)\s+(?P<action>ALLOW|DENY)\s+(?P<proto>TCP|UDP|ICMP)\s+"
                   r"(?P<src>[\d.]+):(?P<sport>\d+)\s+->\s+(?P<dst>[\d.]+):(?P<dport>\d+)\s*$")

# Ports a normal business network expects: SSH, DNS, HTTP, HTTPS, SMTP submission, RDP, SQL*Net, ...
COMMON_PORTS = frozenset({22, 25, 53, 80, 123, 443, 465, 587, 993, 1521, 3389, 5432})


@dataclass(frozen=True)
class FwEvent:
    time: datetime
    action: str
    proto: str
    src: str
    sport: int
    dst: str
    dport: int


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    subject: str
    detail: str


def parse_firewall_log(text: str) -> list[FwEvent]:
    """Parse lines; skip blanks, comments and malformed lines instead of crashing."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        t = datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).astimezone(timezone.utc)
        out.append(FwEvent(t, m["action"], m["proto"], m["src"], int(m["sport"]), m["dst"], int(m["dport"])))
    return sorted(out, key=lambda e: e.time)


def detect_port_scans(events: list[FwEvent], min_ports: int = 15, window_seconds: int = 60) -> list[Alert]:
    """One source touching many DIFFERENT destination ports on one target in a short time.

    A normal client uses a few ports. A scanner sweeps many.
    """
    by_pair: dict[tuple[str, str], list[FwEvent]] = defaultdict(list)
    for e in events:
        by_pair[(e.src, e.dst)].append(e)
    window = timedelta(seconds=window_seconds)
    alerts = []
    for (src, dst), evs in by_pair.items():
        start, best = 0, 0
        for end in range(len(evs)):
            while evs[end].time - evs[start].time > window:
                start += 1
            best = max(best, len({x.dport for x in evs[start:end + 1]}))
        if best >= min_ports:
            alerts.append(Alert("port_scan", "high", src,
                                f"{src} probed {best} different ports on {dst} within {window_seconds}s"))
    return sorted(alerts, key=lambda a: a.subject)


def detect_denied_spikes(events: list[FwEvent], factor: float = 3.0, min_count: int = 20) -> list[Alert]:
    """Per-minute DENY counts. A minute is a spike if it is >= factor x the median and >= min_count.

    This is baselining, the same idea as an AWR baseline in Oracle: compare to normal.
    """
    per_minute: Counter = Counter()
    for e in events:
        if e.action == "DENY":
            per_minute[e.time.replace(second=0)] += 1
    if not per_minute:
        return []
    median = statistics.median(per_minute.values())
    alerts = []
    for minute, count in sorted(per_minute.items()):
        if count >= min_count and count >= factor * max(median, 1):
            alerts.append(Alert("denied_spike", "medium", minute.strftime("%H:%M"),
                                f"{count} denied connections in one minute (median is {median:g})"))
    return alerts


def detect_rare_ports(events: list[FwEvent], known_ports: frozenset[int] = COMMON_PORTS,
                      max_hits: int = 3) -> list[Alert]:
    """ALLOWED traffic to a port that is not on the known list and is seen only a few times.

    Rare + allowed is more interesting than rare + denied: the firewall let it through.
    """
    hits: Counter = Counter()
    sources: dict[int, set[str]] = defaultdict(set)
    for e in events:
        if e.action == "ALLOW" and e.dport not in known_ports:
            hits[e.dport] += 1
            sources[e.dport].add(e.src)
    return [Alert("rare_port", "medium", f"port {p}",
                  f"{n} allowed connection(s) to uncommon port {p} from {', '.join(sorted(sources[p]))}")
            for p, n in sorted(hits.items()) if n <= max_hits]


def analyze(events: list[FwEvent]) -> list[Alert]:
    return detect_port_scans(events) + detect_denied_spikes(events) + detect_rare_ports(events)
