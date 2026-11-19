"""Docker Compose file parser: dependency graph, start order, and a security review (offline, no Docker)."""
from __future__ import annotations

import re

import yaml


class ComposeError(Exception):
    pass


def load(text: str) -> dict:
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or "services" not in doc:
        raise ComposeError("no 'services' key")
    return doc


def depends(svc: dict) -> dict[str, str]:
    """depends_on can be a list (start order only) or a map with conditions (service_healthy ...)."""
    d = svc.get("depends_on") or []
    if isinstance(d, list):
        return {n: "service_started" for n in d}
    return {n: (v or {}).get("condition", "service_started") for n, v in d.items()}


def graph(doc: dict) -> dict[str, list[str]]:
    g = {}
    for name, svc in doc["services"].items():
        deps = depends(svc)
        for d in deps:
            if d not in doc["services"]:
                raise ComposeError(f"service '{name}' depends on unknown service '{d}'")
        g[name] = sorted(deps)
    return g


def start_order(doc: dict) -> list[str]:
    """Topological order: dependencies first. Raises on a cycle."""
    g, order, state = graph(doc), [], {}

    def visit(n, path):
        if state.get(n) == 2:
            return
        if state.get(n) == 1:
            raise ComposeError("dependency cycle: " + " -> ".join(path + [n]))
        state[n] = 1
        for d in g[n]:
            visit(d, path + [n])
        state[n] = 2
        order.append(n)

    for n in sorted(g):
        visit(n, [])
    return order


def _ports(svc: dict) -> list[str]:
    return [str(p) for p in svc.get("ports", [])]


def review(doc: dict) -> list[tuple[str, str, str]]:
    """Return (severity, service, message) for each issue."""
    out = []
    for name, svc in doc["services"].items():
        img = svc.get("image", "")
        if img and "@sha256:" not in img and (":" not in img or img.endswith(":latest")):
            out.append(("HIGH" if img.endswith(":latest") or ":" not in img else "LOW", name, f"image '{img}' is not pinned"))
        if svc.get("privileged"):
            out.append(("CRITICAL", name, "privileged: true gives the container almost all host capabilities and devices"))
        for v in svc.get("volumes", []):
            src = v if isinstance(v, str) else v.get("source", "")
            if "docker.sock" in str(src):
                out.append(("CRITICAL", name, "mounts docker.sock: control of the Docker daemon equals root on the host"))
        if svc.get("network_mode") == "host":
            out.append(("HIGH", name, "network_mode: host removes network isolation"))
        for c in svc.get("cap_add", []):
            out.append(("HIGH" if c in ("SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN") else "MEDIUM", name, f"cap_add {c}"))
        for p in _ports(svc):
            parts = p.split(":")
            if len(parts) == 2 or (len(parts) == 3 and parts[0] in ("0.0.0.0", "")):
                out.append(("MEDIUM", name, f"port {p} is published on all interfaces: bind 127.0.0.1 or put a proxy in front"))
        env = svc.get("environment") or {}
        env = env if isinstance(env, dict) else dict(e.split("=", 1) for e in env if "=" in e)
        for k, v in env.items():
            if re.search(r"(PASS|SECRET|TOKEN|KEY)", k, re.I) and v:
                out.append(("HIGH", name, f"secret '{k}' written in the compose file: use secrets: or an env file kept out of git"))
        if "build" not in svc and not svc.get("user") and not svc.get("privileged"):
            out.append(("LOW", name, "no 'user:' set: the image default (often root) applies"))
        if "healthcheck" not in svc and svc.get("image"):
            out.append(("LOW", name, "no healthcheck"))
        res = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        if not res and not svc.get("mem_limit"):
            out.append(("LOW", name, "no memory/cpu limit: one service can starve the host"))
    for name, svc in doc["services"].items():
        for d, cond in depends(svc).items():
            if cond == "service_healthy" and "healthcheck" not in doc["services"][d]:
                out.append(("MEDIUM", name, f"waits for '{d}' to be healthy but '{d}' defines no healthcheck: it will never start"))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return sorted(out, key=lambda t: (order.index(t[0]), t[1]))
