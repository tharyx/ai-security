"""Docker network simulator: who can reach whom, and what is exposed outside the host.

Rules modelled (Linux, default settings; verify on your Docker version):
- bridge (default 'bridge'): containers talk by IP only (no DNS names), all on one flat network.
- user-defined bridge: built-in DNS by container name; different bridges are isolated from each other.
- host: no network namespace; the container shares the host stack, so it also reaches host localhost services.
- none: only a loopback interface.
- overlay: spans hosts (needs Swarm or a key-value store); same overlay = reachable across nodes.
- Published ports (-p) are the only way the outside world reaches a bridge container.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Publish:
    host_ip: str
    host_port: int
    container_port: int

    @property
    def exposed_to_network(self) -> bool:
        return self.host_ip in ("0.0.0.0", "::", "")


def parse_publish(spec: str) -> Publish:
    parts = spec.split(":")
    if len(parts) == 2:
        parts = ["0.0.0.0"] + parts          # -p 8080:80 binds every interface
    if len(parts) != 3:
        raise ValueError(f"bad -p spec: {spec}")
    return Publish(parts[0], int(parts[1]), int(parts[2]))


class Topology:
    def __init__(self, doc: dict):
        self.host = doc["host"]
        self.nets = {n["name"]: n for n in doc["networks"]}
        self.cs = {c["name"]: c for c in doc["containers"]}

    @classmethod
    def load(cls, path: str) -> "Topology":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def _drivers(self, name: str) -> set[str]:
        return {self.nets[n]["driver"] for n in self.cs[name]["networks"]}

    def shared_networks(self, a: str, b: str) -> list[str]:
        return sorted(set(self.cs[a]["networks"]) & set(self.cs[b]["networks"]))

    def can_reach(self, src: str, dst: str, port: int | None = None) -> tuple[bool, str]:
        s, d = self.cs[src], self.cs[dst]
        if "null" in self._drivers(src):
            return False, f"{src} is on network 'none': loopback only"
        if "null" in self._drivers(dst):
            return False, f"{dst} is on network 'none': nothing can reach it"
        if port is not None and port not in d["listens"]:
            return False, f"{dst} does not listen on {port}"
        if "host" in self._drivers(dst):
            return True, f"{dst} shares the host network: reachable at the host IP"
        shared = self.shared_networks(src, dst)
        if not shared:
            return False, f"no common network ({s['networks']} vs {d['networks']}): isolated"
        net = self.nets[shared[0]]
        if net["driver"] == "overlay":
            return True, f"same overlay '{net['name']}' (even across nodes)"
        if net["user_defined"]:
            return True, f"same user-defined bridge '{net['name']}' (reach by name '{dst}')"
        return True, "same default bridge (reach by IP only; no name resolution)"

    def host_localhost_reachable(self, name: str) -> list[int]:
        """Host-only services (bound to 127.0.0.1) are reachable only from host-network containers."""
        return list(self.host["services_on_localhost"]) if "host" in self._drivers(name) else []

    def exposure(self) -> list[dict]:
        out = []
        for c in self.cs.values():
            for spec in c["publish"]:
                p = parse_publish(spec)
                out.append({
                    "container": c["name"], "binding": f"{p.host_ip}:{p.host_port}->{p.container_port}",
                    "scope": "ALL INTERFACES" if p.exposed_to_network else "loopback only",
                })
            if "host" in self._drivers(c["name"]):
                for port in c["listens"]:
                    out.append({"container": c["name"], "binding": f"host:{port}", "scope": "ALL INTERFACES (host network)"})
        return out

    def findings(self) -> list[str]:
        res = []
        for e in self.exposure():
            if e["scope"].startswith("ALL"):
                res.append(f"{e['container']} listens on {e['binding']} on every interface: bind to 127.0.0.1 or firewall it")
        flat = [c["name"] for c in self.cs.values() if c["networks"] == ["bridge"]]
        if len(flat) > 1:
            res.append(f"{', '.join(flat)} share the default bridge (flat network, no DNS isolation): use user-defined networks")
        return res
