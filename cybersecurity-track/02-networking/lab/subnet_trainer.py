"""Subnetting trainer: generate practice questions and check answers.

Uses the standard-library ``ipaddress`` module as the source of truth, so the
answers are always correct. Questions are seeded, so a quiz can be repeated.

    q = generate_question(random.Random(1), "broadcast")
    q.prompt   -> "What is the broadcast address of 198.51.100.77/26?"
    check_answer(q, "198.51.100.127")
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass

__all__ = ["Question", "KINDS", "subnet_info", "split_subnet", "generate_question",
           "check_answer", "smallest_prefix_for_hosts"]

KINDS = ("hosts", "network", "broadcast", "same_subnet", "prefix_for_hosts", "private")

# Documentation ranges only, so examples are never real networks.
_BASES = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
_PRIVATE_SAMPLES = ["10.4.7.9", "172.16.5.1", "172.32.0.1", "192.168.1.20", "8.8.8.8",
                    "169.254.10.2", "100.64.1.1", "172.31.255.254"]


@dataclass(frozen=True)
class Question:
    kind: str
    prompt: str
    answer: str


def subnet_info(cidr: str) -> dict:
    """Return the facts a network engineer reads from a CIDR block."""
    net = ipaddress.ip_network(cidr, strict=False)
    usable = max(net.num_addresses - 2, 0) if net.prefixlen < 31 else net.num_addresses
    hosts = list(net.hosts()) if net.num_addresses <= 4 else None
    first = hosts[0] if hosts else net.network_address + 1
    last = hosts[-1] if hosts else net.broadcast_address - 1
    return {
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "prefix": net.prefixlen,
        "usable_hosts": usable,
        "first_host": str(first),
        "last_host": str(last),
    }


def split_subnet(cidr: str, new_prefix: int) -> list[str]:
    """Split a block into equal smaller blocks (like VLSM planning)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if new_prefix < net.prefixlen:
        raise ValueError("new_prefix must be longer than the current prefix")
    return [str(s) for s in net.subnets(new_prefix=new_prefix)]


def smallest_prefix_for_hosts(hosts: int) -> int:
    """Longest prefix (smallest subnet) that still fits `hosts` usable addresses."""
    if hosts < 1:
        raise ValueError("hosts must be >= 1")
    for prefix in range(30, 0, -1):
        if 2 ** (32 - prefix) - 2 >= hosts:
            return prefix
    raise ValueError("too many hosts for IPv4")


def _random_host_cidr(rng: random.Random) -> str:
    base = ipaddress.ip_network(rng.choice(_BASES))
    prefix = rng.randint(25, 30)
    addr = base.network_address + rng.randint(1, base.num_addresses - 2)
    return f"{addr}/{prefix}"


def generate_question(rng: random.Random, kind: str | None = None) -> Question:
    kind = kind or rng.choice(KINDS)
    if kind == "hosts":
        prefix = rng.randint(22, 30)
        cidr = f"198.51.100.0/{prefix}" if prefix >= 24 else f"10.0.0.0/{prefix}"
        return Question(kind, f"How many usable host addresses are in {cidr}?",
                        str(subnet_info(cidr)["usable_hosts"]))
    if kind == "network":
        cidr = _random_host_cidr(rng)
        return Question(kind, f"What is the network address of {cidr}?", subnet_info(cidr)["network"])
    if kind == "broadcast":
        cidr = _random_host_cidr(rng)
        return Question(kind, f"What is the broadcast address of {cidr}?", subnet_info(cidr)["broadcast"])
    if kind == "same_subnet":
        cidr = _random_host_cidr(rng)
        net = ipaddress.ip_network(cidr, strict=False)
        a = net.network_address + rng.randint(1, max(net.num_addresses - 2, 1))
        if rng.random() < 0.5:
            b = net.network_address + rng.randint(1, max(net.num_addresses - 2, 1))
        else:
            b = net.broadcast_address + rng.randint(1, 5)  # just outside the subnet
        same = b in net
        return Question(kind, f"With mask /{net.prefixlen}, are {a} and {b} in the same subnet? (yes/no)",
                        "yes" if same else "no")
    if kind == "prefix_for_hosts":
        need = rng.choice([2, 6, 10, 14, 25, 30, 50, 60, 100, 120])
        return Question(kind, f"What is the longest prefix length that gives at least {need} usable hosts?",
                        f"/{smallest_prefix_for_hosts(need)}")
    if kind == "private":
        ip = rng.choice(_PRIVATE_SAMPLES)
        addr = ipaddress.ip_address(ip)
        # RFC 1918 only (10/8, 172.16/12, 192.168/16)
        rfc1918 = any(addr in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        return Question(kind, f"Is {ip} an RFC 1918 private address? (yes/no)", "yes" if rfc1918 else "no")
    raise ValueError(f"unknown kind: {kind}")


def check_answer(question: Question, response: str) -> bool:
    """Compare forgivingly: ignore case, spaces, and a missing leading slash on prefixes."""
    got = response.strip().lower().replace(" ", "")
    want = question.answer.lower()
    if question.kind == "prefix_for_hosts":
        got = "/" + got.lstrip("/")
    if question.kind in ("same_subnet", "private"):
        got = {"y": "yes", "n": "no", "true": "yes", "false": "no"}.get(got, got)
    return got == want
