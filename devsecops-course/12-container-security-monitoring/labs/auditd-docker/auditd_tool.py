"""Lint auditd rules for Docker coverage and detect risky events in an audit.log fixture.

Record format: `type=SYSCALL msg=audit(<epoch>:<serial>): key=value ...`; records of one
event share the serial. auid=4294967295 means 'unset' (no login session). Verify rule
syntax with `man audit.rules` on your system.
"""
from __future__ import annotations

import re
from collections import defaultdict

REQUIRED = {
    "/usr/bin/docker": "docker CLI", "/usr/bin/dockerd": "daemon binary", "/var/lib/docker": "images, containers, volumes",
    "/etc/docker": "daemon.json and TLS material", "/run/docker.sock": "daemon API socket",
    "/var/run/docker.sock": "daemon API socket (legacy path)", "/usr/lib/systemd/system/docker.service": "service unit",
    "/usr/lib/systemd/system/docker.socket": "socket unit", "/usr/bin/containerd": "runtime", "/usr/bin/runc": "low-level runtime",
}
ALLOWED_SOCK_EXES = {"/usr/bin/docker", "/usr/bin/dockerd", "/usr/bin/containerd"}
APPROVED_DOCKER_AUIDS = {1000, 1001}
UNSET = 4294967295
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_rules(text: str) -> list[dict]:
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        if toks[0] == "-w":
            r = {"kind": "watch", "path": toks[1], "perms": "rwxa", "key": ""}
            if "-p" in toks:
                r["perms"] = toks[toks.index("-p") + 1]
            if "-k" in toks:
                r["key"] = toks[toks.index("-k") + 1]
            rules.append(r)
        elif toks[0] == "-a":
            rules.append({"kind": "syscall", "line": line, "key": toks[toks.index("-k") + 1] if "-k" in toks else ""})
    return rules


def coverage(rules: list[dict]) -> list[str]:
    """Required paths with no watch on them (or on a parent directory)."""
    watched = [r["path"] for r in rules if r["kind"] == "watch"]
    missing = []
    for path in REQUIRED:
        if not any(path == w or path.startswith(w.rstrip("/") + "/") for w in watched):
            missing.append(path)
    return missing


def lint(rules: list[dict]) -> list[str]:
    out = []
    for r in rules:
        if r["kind"] == "watch" and not r["key"]:
            out.append(f"watch {r['path']} has no -k key: you will not be able to search for it")
        if r["kind"] == "watch" and r["path"] in ("/etc/docker", "/usr/lib/systemd/system/docker.service") and "w" not in r["perms"]:
            out.append(f"watch {r['path']} does not log writes (-p wa)")
    out += [f"missing watch: {p} ({REQUIRED[p]})" for p in coverage(rules)]
    return out


def parse_log(text: str) -> dict[str, dict]:
    """Group records by event serial: {serial: {'syscall': {...}, 'paths': [{...}]}}."""
    events: dict[str, dict] = defaultdict(lambda: {"syscall": {}, "paths": []})
    for line in text.splitlines():
        m = re.match(r"type=(\w+) msg=audit\((\d+)\.\d+:(\d+)\): (.*)", line)
        if not m:
            continue
        typ, ts, serial, rest = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        kv = {k: v.strip('"') for k, v in KV.findall(rest)}
        ev = events[serial]
        ev["ts"] = ts
        if typ == "SYSCALL":
            ev["syscall"] = kv
        elif typ == "PATH":
            ev["paths"].append(kv)
    return dict(events)


def detect(events: dict[str, dict]) -> list[dict]:
    alerts = []
    for serial, ev in events.items():
        sc, key = ev["syscall"], ev["syscall"].get("key", "")
        exe, auid = sc.get("exe", ""), int(sc.get("auid", UNSET))
        names = [p.get("name", "") for p in ev["paths"]]
        if key == "docker-sock" and exe not in ALLOWED_SOCK_EXES:
            alerts.append({"serial": serial, "rule": "DOCKER_SOCK_ACCESS", "severity": "high",
                           "detail": f"{exe} (uid={sc.get('uid')}, auid={'unset' if auid == UNSET else auid}) opened {names[0] if names else 'docker.sock'}"})
        if key == "docker-config" and any(p.get("nametype") in ("CREATE", "NORMAL") for p in ev["paths"]) and names:
            alerts.append({"serial": serial, "rule": "DOCKER_CONFIG_CHANGE", "severity": "high",
                           "detail": f"{exe} touched {names[0]} (auid={auid}, syscall={sc.get('syscall')})"})
        if key == "docker-exec" and auid not in APPROVED_DOCKER_AUIDS:
            alerts.append({"serial": serial, "rule": "DOCKER_CLI_UNAPPROVED_USER", "severity": "medium",
                           "detail": f"docker CLI used by auid={auid}"})
    return alerts
