"""Synthetic network logs. Documentation IP ranges and *.example domains only. Deterministic (seeded)."""

import random
from datetime import datetime, timedelta, timezone

_RNG = random.Random(2026)
_T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)


def _ts(seconds: float) -> str:
    return (_T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fw(sec, action, proto, src, sport, dst, dport):
    return f"{_ts(sec)} {action} {proto} {src}:{sport} -> {dst}:{dport}"


def build_firewall_log() -> str:
    rng = random.Random(11)
    lines = []
    # normal traffic: clients to web, DNS, Oracle listener
    for i in range(120):
        src = f"192.0.2.{rng.randint(10, 40)}"
        dport = rng.choice([443, 443, 443, 80, 53, 1521])
        lines.append(_fw(i * 5, "ALLOW", "TCP" if dport != 53 else "UDP", src, rng.randint(40000, 60000),
                         "198.51.100.10", dport))
    # port scan: 203.0.113.9 sweeps 30 ports on 198.51.100.10 in 30 seconds (all denied)
    for i, port in enumerate(range(20, 50)):
        lines.append(_fw(200 + i, "DENY", "TCP", "203.0.113.9", 44000 + i, "198.51.100.10", port))
    # denied spike: one minute with many denied connections to RDP from several sources
    for i in range(45):
        lines.append(_fw(400 + i, "DENY", "TCP", f"203.0.113.{100 + i % 5}", 50000 + i, "198.51.100.20", 3389))
    # background denied noise, a few per minute elsewhere
    for minute in (1, 2, 3, 5, 6, 8):
        for j in range(3):
            lines.append(_fw(minute * 60 + j * 10, "DENY", "TCP", "203.0.113.200", 40000 + j, "198.51.100.10", 23))
    # allowed traffic to a rare port (possible backdoor listener / unusual service)
    lines.append(_fw(500, "ALLOW", "TCP", "192.0.2.33", 51000, "198.51.100.10", 4444))
    lines.append(_fw(530, "ALLOW", "TCP", "192.0.2.33", 51001, "198.51.100.10", 4444))
    data = sorted(lines)
    data.insert(3, "# a comment line and a malformed one are skipped by the parser")
    data.insert(4, "garbage line that should be skipped")
    return "\n".join(data) + "\n"


def build_dns_log() -> str:
    rng = random.Random(5)
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    rows = ["timestamp,client_ip,query_name,rcode"]
    # normal client
    for i in range(30):
        name = rng.choice(["www.example", "mail.example", "intranet.corp.example", "updates.vendor.example"])
        rows.append(f"{_ts(i * 7)},192.0.2.21,{name},NOERROR")
    # tunneling client: 25 long random subdomains of one domain, answered
    for i in range(25):
        sub = "".join(rng.choice(alpha) for _ in range(40))
        rows.append(f"{_ts(100 + i * 3)},192.0.2.50,{sub}.t.badzone.example,NOERROR")
    # DGA-like client: many random second-level names that do not exist
    for i in range(20):
        label = "".join(rng.choice(alpha) for _ in range(14))
        rows.append(f"{_ts(200 + i * 2)},192.0.2.60,{label}.example,NXDOMAIN")
    # a few ordinary typos from another client (low NXDOMAIN rate, not enough queries)
    rows.append(f"{_ts(300)},192.0.2.22,wwww.example,NXDOMAIN")
    for i in range(12):
        rows.append(f"{_ts(310 + i)},192.0.2.22,www.example,NOERROR")
    return "\n".join(rows) + "\n"


FIREWALL_LOG = build_firewall_log()
DNS_LOG = build_dns_log()
